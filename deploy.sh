#!/bin/bash

set -e
set -o pipefail

# 변수 파일 불러오기
source ./variables.sh

# 보고서 파일 초기화
REPORT_FILE="deployment_report.txt"
echo "Deployment Report - $(date)" > $REPORT_FILE

# 함수 정의

# 에러 체크 함수
check_exit_status() {
    local status=$?
    if [ $? -ne 0 ]; then
        echo "Error occurred during the last command (exit status: $status). Check the logs for more details." | tee -a $REPORT_FILE
        exit 1
    fi
}

# az cli 설치 함수
install_az_cli() {
    if ! command -v az &> /dev/null; then
        echo "Azure CLI is not installed. Installing now..." | tee -a $REPORT_FILE
        curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
    else
        echo "Azure CLI is already installed." | tee -a $REPORT_FILE
    fi
}

# Azure 로그인 함수
azure_login() {
    read -p "Enter Tenant ID: " TENANT_ID
    read -p "Enter Subscription ID: " SUBSCRIPTION_ID
    az login -t "$TENANT_ID" | tee -a $REPORT_FILE
    az account set -s "$SUBSCRIPTION_ID" | tee -a $REPORT_FILE
}

# 리소스 그룹 생성 함수
create_resource_group() {
    if az group show --name $RG_NAME &> /dev/null; then
        echo "Resource group $RG_NAME already exists." | tee -a $REPORT_FILE
    else
        az group create --location $RG_LOCATION --name $RG_NAME | tee -a $REPORT_FILE
    fi
}

# VNet 및 Subnet 생성 함수
create_vnet_and_subnets() {
    local vnet_name=$1
    local vnet_prefix=$2
    local subnet_name=$3
    local subnet_prefix=$4

    if az network vnet show --name $vnet_name --resource-group $RG_NAME &> /dev/null; then
        echo "VNet $vnet_name already exists." | tee -a $REPORT_FILE
    else
        az network vnet create --name $vnet_name --resource-group $RG_NAME --address-prefixes $vnet_prefix --subnet-name $subnet_name --subnet-prefixes $subnet_prefix | tee -a $REPORT_FILE
    fi
}

# Subnet 생성 함수
create_subnet() {
    local vnet_name=$1
    local subnet_name=$2
    local subnet_prefix=$3

    if az network vnet subnet show --name $subnet_name --vnet-name $vnet_name --resource-group $RG_NAME &> /dev/null; then
        echo "Subnet $subnet_name already exists in $vnet_name." | tee -a $REPORT_FILE
    else
        az network vnet subnet create --name $subnet_name --vnet-name $vnet_name --resource-group $RG_NAME --address-prefixes $subnet_prefix | tee -a $REPORT_FILE
    fi
}

# VNet 피어링 생성 함수
create_vnet_peering() {
    az network vnet peering create --name $HUB_VNET_NAME-$SPOKE_VNET_NAME \
        --resource-group $RG_NAME --vnet-name $HUB_VNET_NAME --remote-vnet $SPOKE_VNET_ID --allow-vnet-access | tee -a $REPORT_FILE
    check_exit_status

    az network vnet peering create --name $SPOKE_VNET_NAME-$HUB_VNET_NAME \
        --resource-group $RG_NAME --vnet-name $SPOKE_VNET_NAME --remote-vnet $HUB_VNET_ID --allow-vnet-access true | tee -a $REPORT_FILE
    check_exit_status
}

# Private DNS 생성 및 링크 함수
create_private_dns_and_link() {
    local zone_name=$1
    local vnet_name=$2
    local link_name=$3
    local registration_enabled=$4

    if az network private-dns zone show --name $zone_name --resource-group $RG_NAME &> /dev/null; then
        echo "Private DNS Zone $zone_name already exists." | tee -a $REPORT_FILE
    else
        az network private-dns zone create --name $zone_name --resource-group $RG_NAME
        check_exit_status
        echo "Private DNS Zone $zone_name created." | tee -a $REPORT_FILE
    fi

    if az network private-dns link vnet show --name "$vnet_name-$link_name" --zone-name $zone_name --resource-group $RG_NAME &> /dev/null; then
        echo "VNet link $link_name for DNS Zone $zone_name already exists." | tee -a $REPORT_FILE
    else
        az network private-dns link vnet create --resource-group $RG_NAME --name "$vnet_name-$link_name" \
            --zone-name $zone_name --virtual-network $vnet_name --registration-enabled $registration_enabled
        check_exit_status
        echo "VNet link $link_name for DNS Zone $zone_name created." | tee -a $REPORT_FILE
    fi
}

# Managed Identity 생성 함수
create_managed_identity() {
    if az identity show --name $MI_NAME --resource-group $RG_NAME &> /dev/null; then
        echo "Managed Identity $MI_NAME already exists." | tee -a $REPORT_FILE
    else
        az identity create --name $MI_NAME --resource-group $RG_NAME --location $RG_LOCATION | tee -a $REPORT_FILE
        check_exit_status
    fi
}

# ACR 생성 함수
create_acr() {
    if az acr show --name $ACR_NAME --resource-group $RG_NAME &> /dev/null; then
        echo "ACR $ACR_NAME already exists." | tee -a $REPORT_FILE
    else
        az acr create --name $ACR_NAME --resource-group $RG_NAME --sku Premium --public-network-enabled false | tee -a $REPORT_FILE
        check_exit_status
    fi
}

# PE 생성 함수
create_private_endpoint() {
    local pe_name=$1
    local vnet_name=$2
    local subnet_name=$3
    local connection_id=$4
    local group_id=$5
    local dns_zone_name=$6
    local dns_zone_group_name=$7

    # 서브넷 ID를 추출
    local subnet_id=$(az network vnet subnet show --name $subnet_name --vnet-name $vnet_name --resource-group $RG_NAME --query "id" -o tsv)

    if az network private-endpoint show --name $pe_name --resource-group $RG_NAME &> /dev/null; then
        echo "Private Endpoint $pe_name already exists." | tee -a $REPORT_FILE
    else
        az network private-endpoint create --name $pe_name --resource-group $RG_NAME --vnet-name $vnet_name \
            --subnet $subnet_id --private-connection-resource-id $connection_id --group-ids $group_id --connection-name "$pe_name-connection" | tee -a $REPORT_FILE
        check_exit_status

        az network private-endpoint dns-zone-group create --resource-group $RG_NAME --endpoint-name $pe_name --name $dns_zone_group_name \
            --private-dns-zone $dns_zone_name --zone-name $dns_zone_name | tee -a $REPORT_FILE
        check_exit_status
    fi
}


# Azure Firewall 생성 함수
create_azure_firewall() {
    if az network firewall show --name $AZ_FIREWALL_NAME --resource-group $RG_NAME &> /dev/null; then
        echo "Azure Firewall $AZ_FIREWALL_NAME already exists." | tee -a $REPORT_FILE
    else
        az network public-ip create --name $AZ_FIREWALL_PIP_NAME --resource-group $RG_NAME --sku Standard --location $RG_LOCATION | tee -a $REPORT_FILE
        check_exit_status
        az network firewall create --name $AZ_FIREWALL_NAME --resource-group $RG_NAME --location $RG_LOCATION --vnet-name $HUB_VNET_NAME | tee -a $REPORT_FILE
        check_exit_status
        az network firewall ip-config create --name $AZ_FIREWALL_IPCONFIG_NAME --firewall-name $AZ_FIREWALL_NAME \
            --resource-group $RG_NAME --vnet-name $HUB_VNET_NAME --public-ip-address $AZ_FIREWALL_PIP_NAME | tee -a $REPORT_FILE
        check_exit_status
        az network firewall network-rule create --firewall-name $AZ_FIREWALL_NAME --resource-group $RG_NAME --name "AllowAKSToInternet" --collection-name "AKSToInternetNetworkRuleCollection" \
            --priority 100 --action "Allow" --source-addresses $SPOKE_AKS_SUBNET_PREFIX --destination-addresses "*" --destination-ports "*" \
            --protocols "Any" | tee -a $REPORT_FILE
        check_exit_status
    fi
}

# AKS 생성 함수
create_aks_cluster() {
    if az aks show --name $AKS_CLUSTER_NAME --resource-group $RG_NAME &> /dev/null; then
        echo "AKS Cluster $AKS_CLUSTER_NAME already exists." | tee -a $REPORT_FILE
    else
        local vnet_snet_id=$(az network vnet subnet show --name $SPOKE_AKS_SUBNET_NAME --resource-group $RG_NAME --vnet-name $SPOKE_VNET_NAME --query "id" -o tsv)
        az aks create --resource-group $RG_NAME --name $AKS_CLUSTER_NAME --load-balancer-sku standard \
            --network-plugin azure --network-plugin-mode overlay --enable-private-cluster --kubernetes-version $AKS_VERSION \
            --node-count $AKS_NODE_COUNT --os-sku Ubuntu --vnet-subnet-id $vnet_snet_id --dns-service-ip $DNS_SERVICE_IP \
            --service-cidr $SERVICE_CIDR --disable-public-fqdn --enable-managed-identity \
            --assign-identity $MI_RESOURCE_ID --assign-kubelet-identity $MI_RESOURCE_ID \
            --attach-acr $ACR_NAME --private-dns-zone "$AKS_DNS_ID" --generate-ssh-keys | tee -a $REPORT_FILE
        check_exit_status
    fi
}

# 스토리지 계정 및 정적 웹사이트 생성 함수
create_storage_account_and_static_website() {
    if az storage account show --name $STORAGE_ACCOUNT_NAME --resource-group $RG_NAME &> /dev/null; then
        echo "Storage Account $STORAGE_ACCOUNT_NAME already exists." | tee -a $REPORT_FILE
    else
        az storage account create --name $STORAGE_ACCOUNT_NAME --resource-group $RG_NAME --location $RG_LOCATION --sku Standard_LRS --kind StorageV2 | tee -a $REPORT_FILE
        check_exit_status
        az storage blob service-properties update --account-name $STORAGE_ACCOUNT_NAME --static-website \
            --404-document $STATIC_WEB_ERROR_PAGE --index-document $STATIC_WEB_INDEX_PAGE | tee -a $REPORT_FILE
        check_exit_status
    fi
}

# NSG 생성 함수
create_nsg() {
    if az network nsg show --name $NSG_NAME --resource-group $RG_NAME &> /dev/null; then
        echo "NSG $NSG_NAME already exists." | tee -a $REPORT_FILE
    else
        az network nsg create --resource-group $RG_NAME --name $NSG_NAME | tee -a $REPORT_FILE
        check_exit_status
        az network nsg rule create --resource-group $RG_NAME --nsg-name $NSG_NAME --name Allow-SSH-RDP-HTTP-HTTPS-8080-8081 \
        --protocol Tcp --direction Inbound --priority 1000 --source-address-prefixes '*' --source-port-ranges '*' \
        --destination-address-prefixes '*' --destination-port-ranges 22 3389 80 443 8080 8081 --access Allow | tee -a $REPORT_FILE
        check_exit_status
    fi
}

# VM 생성 함수
create_vm() {
    local vm_name=$1
    local image=$2
    local public_ip_name=$3

    if az vm show --name $vm_name --resource-group $RG_NAME &> /dev/null; then
        echo "VM $vm_name already exists." | tee -a $REPORT_FILE
    else
        if [ -z "$public_ip_name" ]; then
            az vm create --resource-group $RG_NAME --name $vm_name --image $image --size $VM_SIZE --authentication-type password \
                --admin-username $ADMIN_USERNAME --admin-password $ADMIN_PASSWORD --vnet-name $HUB_VNET_NAME \
                --subnet $HUB_MGMT_SUBNET_NAME --public-ip-address "" --nsg-rule NONE --os-disk-size-gb 128 --security-type Standard | tee -a $REPORT_FILE
            check_exit_status
        else
            az network public-ip create --name $public_ip_name --resource-group $RG_NAME --allocation-method Static --sku Standard | tee -a $REPORT_FILE
            check_exit_status
            az vm create --resource-group $RG_NAME --name $vm_name --image $image --size $VM_SIZE --authentication-type password \
                --admin-username $ADMIN_USERNAME --admin-password $ADMIN_PASSWORD --vnet-name $HUB_VNET_NAME \
                --subnet $HUB_MGMT_SUBNET_NAME --public-ip-address $public_ip_name --nsg-rule NONE --os-disk-size-gb 128 --security-type Standard | tee -a $REPORT_FILE
            check_exit_status
        fi
    fi
}

# Private Endpoint 생성 함수
create_private_dns_and_link() {
    local zone_name=$1
    local vnet_name=$2
    local link_name=$3
    local registration_enabled=$4

    # Private DNS Zone이 이미 존재하는지 확인
    if az network private-dns zone show --name $zone_name --resource-group $RG_NAME &> /dev/null; then
        echo "Private DNS Zone $zone_name already exists." | tee -a $REPORT_FILE
    else
        az network private-dns zone create --name $zone_name --resource-group $RG_NAME
        check_exit_status
        echo "Private DNS Zone $zone_name created." | tee -a $REPORT_FILE
    fi

    # VNet 링크가 이미 존재하는지 확인
    if az network private-dns link vnet show --name "$vnet_name-$link_name" --zone-name $zone_name --resource-group $RG_NAME &> /dev/null; then
        echo "VNet link $link_name for DNS Zone $zone_name already exists." | tee -a $REPORT_FILE
    else
        # registration-enabled를 명확히 설정하여 링크 생성
        if az network private-dns link vnet create --resource-group $RG_NAME --name "$vnet_name-$link_name" \
            --zone-name $zone_name --virtual-network $vnet_name --registration-enabled $registration_enabled 2>/tmp/az_error.log; then
            echo "VNet link $link_name for DNS Zone $zone_name created." | tee -a $REPORT_FILE
        else
            # 충돌 에러를 확인하여 처리
            if grep -q "already linked" /tmp/az_error.log; then
                echo "Conflict occurred: The DNS zone '$zone_name' is already linked to a different VNet. Skipping this step." | tee -a $REPORT_FILE
            else
                echo "An unexpected error occurred while trying to link DNS zone '$zone_name' to VNet '$vnet_name'." | tee -a $REPORT_FILE
                cat /tmp/az_error.log | tee -a $REPORT_FILE
                exit 1
            fi
        fi
    fi
}


# Route Table 생성 함수
create_route_table() {
    local firewall_private_ip=$1

    if az network route-table show --name $ROUTE_TABLE_NAME --resource-group $RG_NAME &> /dev/null; then
        echo "Route Table $ROUTE_TABLE_NAME already exists." | tee -a $REPORT_FILE
    else
        az network route-table create --name $ROUTE_TABLE_NAME --resource-group $RG_NAME --location $RG_LOCATION | tee -a $REPORT_FILE
        check_exit_status
        az network route-table route create --resource-group $RG_NAME --route-table-name $ROUTE_TABLE_NAME --name "defaultRoute" \
            --address-prefix 0.0.0.0/0 --next-hop-type VirtualAppliance --next-hop-ip-address $firewall_private_ip | tee -a $REPORT_FILE
        check_exit_status
        az network vnet subnet update --name $SPOKE_AKS_SUBNET_NAME --vnet-name $SPOKE_VNET_NAME --resource-group $RG_NAME --route-table $ROUTE_TABLE_NAME | tee -a $REPORT_FILE
        check_exit_status
    fi
}

# Azure Front Door 생성 함수
create_front_door() {
    if az network front-door show --name $FRONTDOOR_PROFILE_NAME --resource-group $RG_NAME &> /dev/null; then
        echo "Front Door $FRONTDOOR_PROFILE_NAME already exists." | tee -a $REPORT_FILE
    else
        local static_website_host=$(az storage account show --resource-group $RG_NAME --name $STORAGE_ACCOUNT_NAME --query "primaryEndpoints.web" -o tsv | sed -e 's#https://##' -e 's#/$##')
        az network front-door create --resource-group $RG_NAME --name $FRONTDOOR_PROFILE_NAME --backend-address $static_website_host \
            --accepted-protocols Http Https --forwarding-protocol MatchRequest | tee -a $REPORT_FILE
        check_exit_status

        # Front Door 리소스에 대한 Network Contributor 역할을 할당
        local frontdoor_id=$(az network front-door show --name $FRONTDOOR_PROFILE_NAME --resource-group $RG_NAME --query "id" --output tsv)
        az role assignment create --assignee $MI_CLIENT_ID --role "Network Contributor" --scope $frontdoor_id | tee -a $REPORT_FILE
        check_exit_status
    fi
}

# 기본 NSG 제거 함수
remove_default_nsg() {
    local vm_name=$1

    local nic_name=$(az vm show --resource-group $RG_NAME --name $vm_name --query 'networkProfile.networkInterfaces[0].id' -o tsv | xargs -n 1 basename)
    
    if [ ! -z "$nic_name" ]; then
        az network nic update --resource-group $RG_NAME --name $nic_name --remove networkSecurityGroup | tee -a $REPORT_FILE
        check_exit_status
    fi
}

# NSG 삭제 함수
delete_nsg() {
    local nsg_name=$1

    if az network nsg show --name $nsg_name --resource-group $RG_NAME &> /dev/null; then
        az network nsg delete --resource-group $RG_NAME --name $nsg_name | tee -a $REPORT_FILE
        check_exit_status
    fi
}

# Managed Identity에 필요한 역할 할당
assign_role_to_mi() {
    local mi_client_id=$1
    local resource_id=$2
    local role_name=$3

    az role assignment create --assignee $mi_client_id --role "$role_name" --scope $resource_id | tee -a $REPORT_FILE
    check_exit_status
}

# AZ CLI 설치 절차
install_az_cli

# Azure 로그인 절차
azure_login

# 리소스 그룹 생성
create_resource_group

# Hub VNet 및 Subnet 생성
create_vnet_and_subnets $HUB_VNET_NAME $HUB_VNET_PREFIX $HUB_MGMT_SUBNET_NAME $HUB_MGMT_SUBNET_PREFIX
create_subnet $HUB_VNET_NAME $HUB_FW_SUBNET_NAME $HUB_FW_SUBNET_PREFIX
create_subnet $HUB_VNET_NAME $HUB_PE_SUBNET_NAME $HUB_PE_SUBNET_PREFIX

# Spoke VNet 및 Subnet 생성
create_vnet_and_subnets $SPOKE_VNET_NAME $SPOKE_VNET_PREFIX $SPOKE_AKS_SUBNET_NAME $SPOKE_AKS_SUBNET_PREFIX
create_subnet $SPOKE_VNET_NAME $SPOKE_PE_SUBNET_NAME $SPOKE_PE_SUBNET_PREFIX

# VNet 피어링 생성
HUB_VNET_ID=$(az network vnet show --resource-group $RG_NAME --name $HUB_VNET_NAME --query id --out tsv)
SPOKE_VNET_ID=$(az network vnet show --resource-group $RG_NAME --name $SPOKE_VNET_NAME --query id --out tsv)
create_vnet_peering

# Private DNS 생성 및 링크
create_private_dns_and_link $AKS_DNS_ZONE_NAME $HUB_VNET_NAME $AKS_DNS_LINK_NAME true
create_private_dns_and_link $AKS_DNS_ZONE_NAME $SPOKE_VNET_NAME $AKS_DNS_LINK_NAME true
create_private_dns_and_link $ACR_DNS_ZONE_NAME $HUB_VNET_NAME $ACR_DNS_LINK_NAME false
create_private_dns_and_link $ACR_DNS_ZONE_NAME $SPOKE_VNET_NAME $ACR_DNS_LINK_NAME false
create_private_dns_and_link $SA_DNS_ZONE_NAME $HUB_VNET_NAME $SA_DNS_LINK_NAME false
create_private_dns_and_link $SA_DNS_ZONE_NAME $SPOKE_VNET_NAME $SA_DNS_LINK_NAME false

# # Managed Identity 생성
create_managed_identity
MI_RESOURCE_ID=$(az identity show --name $MI_NAME --resource-group $RG_NAME --query "id" -o tsv)
MI_CLIENT_ID=$(az identity show --name $MI_NAME --resource-group $RG_NAME --query "clientId" -o tsv)
assign_role_to_mi $MI_CLIENT_ID $SPOKE_VNET_ID "Network Contributor"
AKS_DNS_ID=$(az network private-dns zone show -g $RG_NAME -n $AKS_DNS_ZONE_NAME --query id --out tsv)
assign_role_to_mi $MI_CLIENT_ID $AKS_DNS_ID "Private DNS Zone Contributor"

# # ACR 생성 및 Private Endpoint 생성
create_acr
ACR_ID=$(az acr show -g $RG_NAME -n $ACR_NAME --query 'id' -o tsv)
create_private_endpoint $ACR_PE_NAME $SPOKE_VNET_NAME $SPOKE_PE_SUBNET_NAME $ACR_ID "registry" $ACR_DNS_ZONE_NAME $ACR_ZONEGROUP_NAME
assign_role_to_mi $MI_CLIENT_ID $ACR_ID "AcrPush"
assign_role_to_mi $MI_CLIENT_ID $ACR_ID "AcrPull"

# # Azure Firewall 생성
create_azure_firewall
FIREWALL_PRIVATE_IP=$(az network firewall show --name $AZ_FIREWALL_NAME --resource-group $RG_NAME --query "ipConfigurations[0].privateIPAddress" -o tsv)

# # AKS 클러스터 생성
VNET_SNET_ID=$(az network vnet subnet show --name $SPOKE_AKS_SUBNET_NAME --resource-group $RG_NAME --vnet-name $SPOKE_VNET_NAME --query "id" -o tsv)
create_aks_cluster
AKS_CLUSTER_ID=$(az aks show --name $AKS_CLUSTER_NAME --resource-group $RG_NAME --query "id" -o tsv)
assign_role_to_mi $MI_CLIENT_ID $AKS_CLUSTER_ID "Azure Kubernetes Service RBAC Cluster Admin"

# 스토리지 계정 및 정적 웹사이트 생성
create_storage_account_and_static_website
STORAGE_ACCOUNT_ID=$(az storage account show --name $STORAGE_ACCOUNT_NAME --resource-group $RG_NAME --query "id" --output tsv)
create_private_endpoint $SA_PE_NAME $HUB_VNET_NAME $HUB_PE_SUBNET_NAME $STORAGE_ACCOUNT_ID "blob" $SA_DNS_ZONE_NAME $SA_DNS_ZONEGROUP_NAME
assign_role_to_mi $MI_CLIENT_ID $STORAGE_ACCOUNT_ID "Storage Blob Data Contributor"

# NSG 생성 및 적용
create_nsg
az network vnet subnet update --vnet-name $HUB_VNET_NAME --name $HUB_MGMT_SUBNET_NAME --resource-group $RG_NAME --network-security-group $NSG_NAME | tee -a $REPORT_FILE
check_exit_status

# Bastion VM 생성
create_vm $BASTION_VM_NAME $WIN_IMAGE $BASTION_PUBLIC_IP_NAME

# GitLab 및 Jenkins VM 생성
create_vm $GITLAB_VM_NAME $UBUNTU_IMAGE ""
create_vm $JENKINS_VM_NAME $UBUNTU_IMAGE ""

# 기본 NSG 제거 및 NSG 삭제
remove_default_nsg $BASTION_VM_NAME
remove_default_nsg $GITLAB_VM_NAME
remove_default_nsg $JENKINS_VM_NAME

delete_nsg "${BASTION_VM_NAME}NSG"
delete_nsg "${GITLAB_VM_NAME}NSG"
delete_nsg "${JENKINS_VM_NAME}NSG"

# Route Table 생성 및 AKS 서브넷에 연결
create_route_table $FIREWALL_PRIVATE_IP

# Azure Front Door 생성
create_front_door
FRONTDOOR_ID=$(az network front-door show --name $FRONTDOOR_PROFILE_NAME --resource-group $RG_NAME --query "id" --output tsv)
assign_role_to_mi $MI_CLIENT_ID $FRONTDOOR_ID "Network Contributor"

# 스크립트 실행 완료 메시지
echo "Deployment script completed. Check $REPORT_FILE for details."