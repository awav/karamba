#!/bin/bash

################################################################################
# VPN Protection Setup for Public IP Servers
# Options: WireGuard VPN, Tailscale Mesh VPN, or Both
# Usage: sudo ./vpn-protection-setup.sh
################################################################################

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    error "Please run as root (use sudo)"
fi

clear
echo "=========================================="
echo "  VPN Protection Setup for Public IP"
echo "=========================================="
echo ""
echo "This script offers multiple VPN solutions to protect your server:"
echo ""
echo "1) WireGuard VPN (Self-hosted, maximum control)"
echo "2) Tailscale (Mesh VPN, easiest setup)"
echo "3) Both (WireGuard + Tailscale for flexibility)"
echo "4) Advanced Protection (VPN + Port Knocking + Fail2ban tuning)"
echo ""
echo "0) Exit"
echo ""
read -p "Select option: " choice

case $choice in
    1)
        VPN_TYPE="wireguard"
        ;;
    2)
        VPN_TYPE="tailscale"
        ;;
    3)
        VPN_TYPE="both"
        ;;
    4)
        VPN_TYPE="advanced"
        ;;
    0)
        echo "Exiting..."
        exit 0
        ;;
    *)
        error "Invalid option"
        ;;
esac

################################################################################
# WireGuard VPN Setup
################################################################################

setup_wireguard() {
    log "Setting up WireGuard VPN..."
    
    apt-get update
    apt-get install -y wireguard wireguard-tools qrencode
    
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
    sysctl -p
    
    cd /etc/wireguard
    umask 077
    wg genkey | tee server_private.key | wg pubkey > server_public.key
    SERVER_PRIVATE_KEY=$(cat server_private.key)
    SERVER_PUBLIC_KEY=$(cat server_public.key)
    
    SERVER_PUBLIC_IP=$(curl -s ifconfig.me)
    
    cat > /etc/wireguard/wg0.conf << EOF
[Interface]
Address = 10.8.0.1/24
ListenPort = 51820
PrivateKey = $SERVER_PRIVATE_KEY
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

# Client configurations will be added below
# Use: wg-quick up wg0 to start
# Use: wg-quick down wg0 to stop
EOF
    
    ufw allow 51820/udp comment 'WireGuard VPN'
    
    cat > /usr/local/bin/add-wireguard-client.sh << 'EOFSCRIPT'
#!/bin/bash

if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root"
    exit 1
fi

if [ $# -lt 1 ]; then
    echo "Usage: $0 <client-name>"
    echo "Example: $0 laptop"
    exit 1
fi

CLIENT_NAME=$1
SERVER_PUBLIC_KEY=$(cat /etc/wireguard/server_public.key)
SERVER_ENDPOINT=$(curl -s ifconfig.me)
CLIENTS_DIR="/etc/wireguard/clients"
mkdir -p $CLIENTS_DIR

# Find next available IP
LAST_IP=$(grep -oP "AllowedIPs = 10\.8\.0\.\K\d+" /etc/wireguard/wg0.conf | sort -n | tail -1)
if [ -z "$LAST_IP" ]; then
    CLIENT_IP=2
else
    CLIENT_IP=$((LAST_IP + 1))
fi

# Generate client keys
cd $CLIENTS_DIR
wg genkey | tee ${CLIENT_NAME}_private.key | wg pubkey > ${CLIENT_NAME}_public.key
CLIENT_PRIVATE_KEY=$(cat ${CLIENT_NAME}_private.key)
CLIENT_PUBLIC_KEY=$(cat ${CLIENT_NAME}_public.key)

# Create client config
cat > ${CLIENT_NAME}.conf << EOF
[Interface]
PrivateKey = $CLIENT_PRIVATE_KEY
Address = 10.8.0.$CLIENT_IP/24
DNS = 1.1.1.1, 8.8.8.8

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
Endpoint = $SERVER_ENDPOINT:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF

# Add client to server config
cat >> /etc/wireguard/wg0.conf << EOF

# Client: $CLIENT_NAME
[Peer]
PublicKey = $CLIENT_PUBLIC_KEY
AllowedIPs = 10.8.0.$CLIENT_IP/32
EOF

# Restart WireGuard
systemctl restart wg-quick@wg0

echo ""
echo "=========================================="
echo "  WireGuard Client: $CLIENT_NAME"
echo "=========================================="
echo ""
echo "Client configuration saved to: $CLIENTS_DIR/${CLIENT_NAME}.conf"
echo ""
echo "To connect from the client device:"
echo "1. Install WireGuard"
echo "2. Copy the config file to the client"
echo "3. Import and activate the VPN"
echo ""
echo "Mobile device? Generate QR code:"
echo "  qrencode -t ansiutf8 < $CLIENTS_DIR/${CLIENT_NAME}.conf"
echo ""
echo "Client IP: 10.8.0.$CLIENT_IP"
echo "=========================================="
EOFSCRIPT
    
    chmod +x /usr/local/bin/add-wireguard-client.sh
    
    # Enable and start WireGuard
    systemctl enable wg-quick@wg0
    systemctl start wg-quick@wg0
    
    log "WireGuard VPN installed successfully!"
    echo ""
    info "Server Public Key: $SERVER_PUBLIC_KEY"
    info "Server Endpoint: $SERVER_PUBLIC_IP:51820"
    info "VPN Network: 10.8.0.0/24"
    echo ""
    info "Add clients with: sudo /usr/local/bin/add-wireguard-client.sh <client-name>"
    echo ""
}

################################################################################
# Tailscale Setup
################################################################################

setup_tailscale() {
    log "Setting up Tailscale Mesh VPN..."
    
    curl -fsSL https://pkgs.tailscale.com/stable/ubuntu/$(lsb_release -cs).noarmor.gpg | tee /usr/share/keyrings/tailscale-archive-keyring.gpg >/dev/null
    curl -fsSL https://pkgs.tailscale.com/stable/ubuntu/$(lsb_release -cs).tailscale-keyring.list | tee /etc/apt/sources.list.d/tailscale.list
    
    apt-get update
    apt-get install -y tailscale
    
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
    sysctl -p
    
    log "Tailscale installed successfully!"
    echo ""
    warn "IMPORTANT: You need to authenticate Tailscale"
    echo ""
    echo "Run one of these commands:"
    echo ""
    echo "Basic setup (personal use):"
    echo "  sudo tailscale up"
    echo ""
    echo "As an exit node (route all traffic):"
    echo "  sudo tailscale up --advertise-exit-node"
    echo ""
    echo "As a subnet router (access other devices on this network):"
    echo "  sudo tailscale up --advertise-routes=192.168.1.0/24"
    echo ""
    echo "With SSH enabled:"
    echo "  sudo tailscale up --ssh"
    echo ""
    info "After running the command, visit the URL shown to authenticate"
    echo ""
}

################################################################################
# Advanced Protection Setup
################################################################################

setup_advanced_protection() {
    log "Setting up advanced protection measures..."
    
    if [ "$1" != "skip-vpn" ]; then
        setup_wireguard
        setup_tailscale
    fi
    
    log "Installing port knocking (knockd)..."
    apt-get install -y knockd
    
    cat > /etc/knockd.conf << 'EOF'
[options]
    UseSyslog
    
[openSSH]
    sequence    = 7000,8000,9000
    seq_timeout = 5
    command     = /usr/sbin/ufw allow from %IP% to any port 2222
    tcpflags    = syn

[closeSSH]
    sequence    = 9000,8000,7000
    seq_timeout = 5
    command     = /usr/sbin/ufw delete allow from %IP% to any port 2222
    tcpflags    = syn
EOF

    sed -i 's/START_KNOCKD=0/START_KNOCKD=1/' /etc/default/knockd
    systemctl enable knockd
    systemctl start knockd
    
    log "Enhancing fail2ban configuration..."
    
    cat > /etc/fail2ban/jail.d/aggressive.local << 'EOF'
[DEFAULT]
bantime = 86400
findtime = 3600
maxretry = 2
destemail = root@localhost
sendername = Fail2Ban-Aggressive
action = %(action_mwl)s

[sshd]
enabled = true
maxretry = 2
bantime = 86400
findtime = 600

[sshd-ddos]
enabled = true
maxretry = 2
EOF
    
    log "Installing GeoIP tools for country-based blocking..."
    apt-get install -y geoip-bin geoip-database
    
    cat > /usr/local/bin/block-countries.sh << 'EOFSCRIPT'
#!/bin/bash
# Block specific countries from accessing the server
# Usage: ./block-countries.sh CN RU KP

if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root"
    exit 1
fi

# Create ipset if not exists
ipset create -exist blocked_countries hash:net

for country in "$@"; do
    echo "Blocking country: $country"
    
    # Download country IP list
    COUNTRY_ZONES=$(curl -s "https://www.ipdeny.com/ipblocks/data/countries/${country,,}.zone")
    
    # Add to ipset
    for ip in $COUNTRY_ZONES; do
        ipset add blocked_countries $ip 2>/dev/null
    done
done

# Add iptables rule
iptables -I INPUT -m set --match-set blocked_countries src -j DROP

echo "Blocked countries: $@"
echo "To persist across reboots, add to startup scripts"
EOFSCRIPT
    
    chmod +x /usr/local/bin/block-countries.sh
    
    log "Setting up connection rate limiting..."
    
    cat > /etc/ufw/before.rules.append << 'EOF'

# Rate limiting for new connections
-A ufw-before-input -p tcp --dport 2222 -m state --state NEW -m recent --set --name SSH
-A ufw-before-input -p tcp --dport 2222 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 --name SSH -j DROP
EOF
    
    cp /etc/ufw/before.rules /etc/ufw/before.rules.backup
    cat /etc/ufw/before.rules.append >> /etc/ufw/before.rules
    
    systemctl restart fail2ban
    ufw reload
    
    log "Advanced protection measures installed!"
    echo ""
    info "Port Knocking Installed:"
    echo "  Open SSH: knock <server-ip> 7000 8000 9000"
    echo "  Close SSH: knock <server-ip> 9000 8000 7000"
    echo ""
    info "Install 'knock' client on your local machine:"
    echo "  Ubuntu/Debian: sudo apt-get install knockd"
    echo "  macOS: brew install knock"
    echo ""
    info "Enhanced fail2ban: More aggressive banning (2 attempts = 24h ban)"
    echo ""
}

################################################################################
# Firewall Hardening for VPN-only Access
################################################################################

harden_firewall_for_vpn() {
    log "Configuring firewall for VPN-only access..."
    
    echo ""
    warn "IMPORTANT: This will restrict SSH access to VPN users only!"
    echo ""
    read -p "Current SSH port (default 2222): " SSH_PORT
    SSH_PORT=${SSH_PORT:-2222}
    
    read -p "WireGuard VPN network (default 10.8.0.0/24): " VPN_NETWORK
    VPN_NETWORK=${VPN_NETWORK:-10.8.0.0/24}
    
    echo ""
    warn "After applying these rules, you MUST connect via VPN to access SSH!"
    read -p "Are you sure? (yes/no): " confirm
    
    if [ "$confirm" != "yes" ]; then
        warn "Skipping firewall hardening"
        return
    fi
    
    ufw delete allow $SSH_PORT/tcp 2>/dev/null || true
    ufw allow from $VPN_NETWORK to any port $SSH_PORT proto tcp comment 'SSH via VPN only'
    ufw allow 51820/udp comment 'WireGuard VPN'
    ufw reload
    
    log "Firewall hardened - SSH now only accessible via VPN!"
    warn "Make sure you have VPN access before disconnecting!"
}

################################################################################
# Main Installation
################################################################################

case $VPN_TYPE in
    wireguard)
        setup_wireguard
        echo ""
        read -p "Restrict SSH to VPN-only access? (y/n): " restrict
        if [ "$restrict" = "y" ]; then
            harden_firewall_for_vpn
        fi
        ;;
    tailscale)
        setup_tailscale
        ;;
    both)
        setup_wireguard
        setup_tailscale
        echo ""
        read -p "Restrict SSH to VPN-only access? (y/n): " restrict
        if [ "$restrict" = "y" ]; then
            harden_firewall_for_vpn
        fi
        ;;
    advanced)
        setup_advanced_protection
        echo ""
        read -p "Restrict SSH to VPN-only access? (y/n): " restrict
        if [ "$restrict" = "y" ]; then
            harden_firewall_for_vpn
        fi
        ;;
esac

################################################################################
# Final Instructions
################################################################################

echo ""
echo "=========================================="
echo "  VPN Protection Setup Complete!"
echo "=========================================="
echo ""

case $VPN_TYPE in
    wireguard|both|advanced)
        echo "WIREGUARD VPN:"
        echo "  - Server running on port 51820 (UDP)"
        echo "  - VPN Network: 10.8.0.0/24"
        echo "  - Add clients: sudo /usr/local/bin/add-wireguard-client.sh <name>"
        echo "  - Check status: sudo wg show"
        echo ""
        ;;
esac

case $VPN_TYPE in
    tailscale|both|advanced)
        echo "TAILSCALE:"
        echo "  - Authenticate with: sudo tailscale up"
        echo "  - Check status: sudo tailscale status"
        echo "  - Manage at: https://login.tailscale.com/admin"
        echo ""
        ;;
esac

if [ "$VPN_TYPE" = "advanced" ]; then
    echo "ADVANCED FEATURES:"
    echo "  - Port knocking enabled (sequence: 7000 8000 9000)"
    echo "  - Aggressive fail2ban (2 attempts = 24h ban)"
    echo "  - GeoIP blocking available: sudo /usr/local/bin/block-countries.sh CN RU"
    echo ""
fi

echo "NEXT STEPS:"
echo "  1. Setup VPN clients on your devices"
echo "  2. Test VPN connectivity"
echo "  3. Consider restricting SSH to VPN-only access"
echo "  4. Monitor logs: sudo journalctl -u wg-quick@wg0 -f"
echo ""
echo "=========================================="
