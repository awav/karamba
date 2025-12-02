#!/bin/bash

################################################################################
# Security and Health Check Script
# Purpose: Perform routine security and system health checks
# Usage: sudo ./security-check.sh
################################################################################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PASS="${GREEN}[PASS]${NC}"
FAIL="${RED}[FAIL]${NC}"
WARN="${YELLOW}[WARN]${NC}"
INFO="${BLUE}[INFO]${NC}"

echo "=========================================="
echo "  System Security & Health Check"
echo "  $(date)"
echo "=========================================="
echo ""

################################################################################
# 1. User Account Security
################################################################################

echo -e "${BLUE}=== User Account Security ===${NC}"

echo -n "Checking for non-root users with UID 0... "
NON_ROOT_UID0=$(awk -F: '($3 == "0") {print $1}' /etc/passwd | grep -v root)
if [ -z "$NON_ROOT_UID0" ]; then
    echo -e "$PASS"
else
    echo -e "$FAIL"
    echo "  Users with UID 0: $NON_ROOT_UID0"
fi

echo -n "Checking for users without passwords... "
NO_PASS=$(awk -F: '($2 == "") {print $1}' /etc/shadow 2>/dev/null)
if [ -z "$NO_PASS" ]; then
    echo -e "$PASS"
else
    echo -e "$FAIL"
    echo "  Users without passwords: $NO_PASS"
fi

echo -n "Active user accounts: "
ACTIVE_USERS=$(grep -E ":/bin/(bash|sh|zsh)" /etc/passwd | wc -l)
echo -e "${GREEN}$ACTIVE_USERS${NC}"

LOCKED=$(passwd -Sa 2>/dev/null | grep -c " L ")
echo -n "Locked accounts: "
echo -e "${YELLOW}$LOCKED${NC}"

echo ""

################################################################################
# 2. SSH Security
################################################################################

echo -e "${BLUE}=== SSH Security ===${NC}"

echo -n "Root login disabled... "
if grep -q "^PermitRootLogin no" /etc/ssh/sshd_config; then
    echo -e "$PASS"
else
    echo -e "$FAIL"
    grep "PermitRootLogin" /etc/ssh/sshd_config | grep -v "^#"
fi

echo -n "SSH port configuration... "
SSH_PORT=$(grep "^Port" /etc/ssh/sshd_config | awk '{print $2}')
if [ "$SSH_PORT" != "22" ] && [ ! -z "$SSH_PORT" ]; then
    echo -e "$PASS (Port: $SSH_PORT)"
else
    echo -e "$WARN (Using default port 22)"
fi

echo -n "Password authentication... "
PASS_AUTH=$(grep "^PasswordAuthentication" /etc/ssh/sshd_config | awk '{print $2}')
if [ "$PASS_AUTH" = "no" ]; then
    echo -e "$PASS (Disabled - using keys only)"
else
    echo -e "$WARN (Enabled)"
fi

echo -n "Failed SSH login attempts (last 24h)... "
FAILED_SSH=$(grep "Failed password" /var/log/auth.log 2>/dev/null | grep "$(date +%b\ %d)" | wc -l)
if [ $FAILED_SSH -lt 5 ]; then
    echo -e "${GREEN}$FAILED_SSH${NC}"
elif [ $FAILED_SSH -lt 20 ]; then
    echo -e "${YELLOW}$FAILED_SSH${NC}"
else
    echo -e "${RED}$FAILED_SSH${NC}"
fi

echo ""

################################################################################
# 3. Firewall Status
################################################################################

echo -e "${BLUE}=== Firewall Status ===${NC}"

echo -n "UFW firewall status... "
UFW_STATUS=$(ufw status | grep -i "Status:" | awk '{print $2}')
if [ "$UFW_STATUS" = "active" ]; then
    echo -e "$PASS"
else
    echo -e "$FAIL"
fi

echo "Active firewall rules:"
ufw status numbered 2>/dev/null | grep -v "^$" | tail -n +4 | head -10

echo ""

################################################################################
# 4. Fail2ban Status
################################################################################

echo -e "${BLUE}=== Fail2ban Status ===${NC}"

if systemctl is-active --quiet fail2ban; then
    echo -e "$PASS Fail2ban is active"
    
    BANNED=$(fail2ban-client status sshd 2>/dev/null | grep "Currently banned" | awk '{print $NF}')
    echo "Currently banned IPs: $BANNED"
    
    TOTAL_BANS=$(fail2ban-client status sshd 2>/dev/null | grep "Total banned" | awk '{print $NF}')
    echo "Total bans (session): $TOTAL_BANS"
else
    echo -e "$FAIL Fail2ban is not running"
fi

echo ""

################################################################################
# 5. Disk Usage and Quotas
################################################################################

echo -e "${BLUE}=== Disk Usage ===${NC}"

df -h / | grep -v "Filesystem"

echo ""
echo "User Disk Quotas:"
if command -v repquota &> /dev/null; then
    repquota -a 2>/dev/null | grep -v "^#" | grep -v "^root" | head -10
else
    echo "  Quotas not configured"
fi

echo ""

################################################################################
# 6. System Resources
################################################################################

echo -e "${BLUE}=== System Resources ===${NC}"

LOAD=$(uptime | awk -F'load average:' '{print $2}')
echo "Load average:$LOAD"

FREE_MEM=$(free -h | grep Mem: | awk '{print "Total: "$2" | Used: "$3" | Free: "$4" | Available: "$7}')
echo "Memory: $FREE_MEM"

echo ""
echo "Top 5 CPU processes:"
ps aux --sort=-%cpu | head -6 | tail -5 | awk '{printf "  %s: %s%%\n", $11, $3}'

echo ""

################################################################################
# 7. Service Status
################################################################################

echo -e "${BLUE}=== Critical Services ===${NC}"

SERVICES=("ssh" "ufw" "fail2ban" "auditd" "rsyslog")
for service in "${SERVICES[@]}"; do
    echo -n "$service... "
    if systemctl is-active --quiet $service; then
        echo -e "$PASS"
    else
        echo -e "$FAIL"
    fi
done

echo ""

################################################################################
# 8. Security Updates
################################################################################

echo -e "${BLUE}=== Security Updates ===${NC}"

echo -n "Checking for updates... "
apt-get update > /dev/null 2>&1
SECURITY_UPDATES=$(apt-get -s upgrade | grep -i security | wc -l)

if [ $SECURITY_UPDATES -eq 0 ]; then
    echo -e "$PASS (System is up to date)"
else
    echo -e "$WARN ($SECURITY_UPDATES security updates available)"
    apt list --upgradable 2>/dev/null | grep -i security | head -5
fi

echo ""

################################################################################
# 9. Log Analysis
################################################################################

echo -e "${BLUE}=== Recent Security Events ===${NC}"

echo "Recent sudo usage (last 10):"
grep sudo /var/log/auth.log 2>/dev/null | tail -10 | awk '{print "  " $1, $2, $3, $9, $10, $11, $12}'

echo ""

echo -n "Recent user account changes... "
NEW_USERS=$(grep "new user" /var/log/auth.log 2>/dev/null | grep "$(date +%b\ %d)" | wc -l)
if [ $NEW_USERS -eq 0 ]; then
    echo -e "${GREEN}None${NC}"
else
    echo -e "${YELLOW}$NEW_USERS${NC}"
    grep "new user" /var/log/auth.log 2>/dev/null | grep "$(date +%b\ %d)"
fi

echo ""

################################################################################
# 10. Listening Ports
################################################################################

echo -e "${BLUE}=== Network Listening Ports ===${NC}"

echo "Open ports:"
ss -tulpn | grep LISTEN | awk '{print "  " $1, $5, $7}' | column -t

echo ""

################################################################################
# 11. File Integrity
################################################################################

echo -e "${BLUE}=== File Integrity ===${NC}"

echo -n "Checking for world-writable files in /etc... "
WRITABLE=$(find /etc -xdev -type f -perm -002 2>/dev/null | wc -l)
if [ $WRITABLE -eq 0 ]; then
    echo -e "$PASS"
else
    echo -e "$WARN ($WRITABLE files found)"
fi

echo -n "SUID files... "
SUID_COUNT=$(find / -xdev -type f -perm -4000 2>/dev/null | wc -l)
echo -e "${INFO} $SUID_COUNT files"

echo ""

################################################################################
# 12. Process Monitoring
################################################################################

echo -e "${BLUE}=== Process Monitoring ===${NC}"

echo "Active login sessions:"
who | awk '{print "  " $1, $2, $3, $4, $5}'

echo ""
echo "Processes with network connections:"
netstat -tunapl 2>/dev/null | grep ESTABLISHED | awk '{print $7}' | cut -d'/' -f2 | sort | uniq -c | sort -rn | head -5

echo ""

################################################################################
# Summary and Recommendations
################################################################################

echo "=========================================="
echo -e "${BLUE}=== Recommendations ===${NC}"
echo "=========================================="

RECOMMENDATIONS=()

if ! systemctl is-active --quiet fail2ban; then
    RECOMMENDATIONS+=("Start fail2ban service")
fi

if [ $SECURITY_UPDATES -gt 0 ]; then
    RECOMMENDATIONS+=("Install $SECURITY_UPDATES security updates")
fi

if [ "$PASS_AUTH" != "no" ]; then
    RECOMMENDATIONS+=("Consider disabling SSH password authentication")
fi

if [ "$SSH_PORT" = "22" ] || [ -z "$SSH_PORT" ]; then
    RECOMMENDATIONS+=("Consider changing SSH to non-standard port")
fi

DISK_USAGE=$(df / | tail -1 | awk '{print $5}' | sed 's/%//')
if [ $DISK_USAGE -gt 80 ]; then
    RECOMMENDATIONS+=("Disk usage is at ${DISK_USAGE}% - consider cleanup")
fi

if [ ${#RECOMMENDATIONS[@]} -eq 0 ]; then
    echo -e "${GREEN}No immediate recommendations${NC}"
else
    for i in "${!RECOMMENDATIONS[@]}"; do
        echo -e "${YELLOW}$((i+1)).${NC} ${RECOMMENDATIONS[$i]}"
    done
fi

echo ""
echo "=========================================="
echo "Check completed at $(date)"
echo "=========================================="
