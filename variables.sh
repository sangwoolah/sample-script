# variables.sh

# 변수 설정
export MSYS_NO_PATHCONV=1

# 지역 설정
export RG_LOCATION="koreacentral" # 리소스 그룹 생성 위치

# 리소스 그룹 이름
export RG_NAME="peterlah-rg" # 리소스 그룹 이름

# Hub Network 설정
export HUB_VNET_NAME="hub-vnet" # Hub VNet 이름
export HUB_VNET_PREFIX="10.0.0.0/16" # Hub VNet 주소 범위
export HUB_MGMT_SUBNET_NAME="hub-mgmt-subnet" # 관리용 서브넷 이름
export HUB_MGMT_SUBNET_PREFIX="10.0.0.0/24" # 관리용 서브넷 주소 범위
export HUB_FW_SUBNET_NAME="AzureFirewallSubnet" # Azure Firewall 서브넷 이름
export HUB_FW_SUBNET_PREFIX="10.0.1.0/24" # Azure Firewall 서브넷 주소 범위
export HUB_PE_SUBNET_NAME="hub-pe-subnet" # Private Endpoint 서브넷 이름
export HUB_PE_SUBNET_PREFIX="10.0.2.0/24" # Private Endpoint 서브넷 주소 범위

# Spoke Network 설정
export SPOKE_VNET_NAME="spoke-vnet" # Spoke VNet 이름
export SPOKE_VNET_PREFIX="20.0.0.0/16" # Spoke VNet 주소 범위
export SPOKE_AKS_SUBNET_NAME="spoke-aks-subnet" # AKS 서브넷 이름
export SPOKE_AKS_SUBNET_PREFIX="20.0.0.0/18" # AKS 서브넷 주소 범위
export SPOKE_PE_SUBNET_NAME="spoke-pe-subnet" # Private Endpoint 서브넷 이름
export SPOKE_PE_SUBNET_PREFIX="20.0.64.0/24" # Private Endpoint 서브넷 주소 범위

# Private DNS Zone 설정
export AKS_DNS_ZONE_NAME="privatelink.koreacentral.azmk8s.io"
export ACR_DNS_ZONE_NAME="privatelink.azurecr.io"
export SA_DNS_ZONE_NAME="privatelink.blob.core.windows.net"
export AKS_DNS_LINK_NAME="vnet-aks-dns-link"
export ACR_DNS_LINK_NAME="vnet-acr-dns-link"
export SA_DNS_LINK_NAME="vnet-sa-dns-link"

# Managed Identity 설정
export MI_NAME="peterlah-mi" # Managed Identity 이름

# ACR 설정
export ACR_NAME="lswacr0621" # Azure Container Registry 이름
export ACR_PE_NAME="acr-endpoint" # Private Endpoint 이름
export ACR_ZONEGROUP_NAME="acr-zone-group" # Private DNS Zone Group 이름

# Azure Firewall 설정
export AZ_FIREWALL_PIP_NAME="azure-firewall-pip" # Public IP 이름
export AZ_FIREWALL_NAME="peterlah-firewall" # Azure Firewall 이름
export AZ_FIREWALL_IPCONFIG_NAME="azure-firewall-ipconfig" # IP Configuration 이름

# AKS 설정
export AKS_CLUSTER_NAME="aks-cluster" # AKS 클러스터 이름
export AKS_VERSION="1.28.10" # AKS 버전
export AKS_NODE_COUNT="2" # AKS 노드 수
export DNS_SERVICE_IP="30.0.0.10" # DNS 서비스 IP
export SERVICE_CIDR="30.0.0.0/16" # 서비스 CIDR
export POD_CIDR="30.100.0.0/16" # POD CIDR

# 스토리지 계정 설정
export STORAGE_ACCOUNT_NAME="lswsaweb0806" # 스토리지 계정 이름
export STATIC_WEB_ERROR_PAGE="404.html" # 에러 페이지 경로
export STATIC_WEB_INDEX_PAGE="index.html" # 인덱스 페이지 경로
export SA_PE_NAME="sa-endpoint" # Private Endpoint 이름
export SA_ZONEGROUP_NAME="sa-zone-group" # Private DNS Zone Group 이름

# NSG 설정
export NSG_NAME="vm-nsg" # 네트워크 보안 그룹 이름

# VM 설정
export BASTION_PUBLIC_IP_NAME="bastion-public-ip" # Bastion Public IP 이름
export BASTION_VM_NAME="BASTION-VM" # Bastion VM 이름
export GITLAB_VM_NAME="GITLAB-VM" # Bastion VM 이름
export JENKINS_VM_NAME="JENKINS-VM" # Bastion VM 이름
export ADMIN_USERNAME="azureadmin" # VM 관리자 계정 이름
export ADMIN_PASSWORD="@Password!!1234" # VM 관리자 계정 비밀번호
export VM_SIZE="Standard_D4s_v3" # VM 크기
export WIN_IMAGE="MicrosoftWindowsDesktop:Windows-10:win10-21h2-ent:19044.4529.240607" # 윈도우 10 이미지
export UBUNTU_IMAGE="Canonical:0001-com-ubuntu-server-focal:20_04-lts-gen2:latest" # 우분투 이미지

# UDR 설정
export ROUTE_TABLE_NAME="aksRouteTable"

# Front Door 설정
export FRONTDOOR_PROFILE_NAME="fd-profile"
export FRONTDOOR_ENDPOINT_NAME="fd-endpoint"