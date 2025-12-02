# Complete Ubuntu Security & VPN Toolkit

## What's Included

This is a complete security toolkit for Ubuntu servers with public IP addresses, especially designed for multi-user environments like NVIDIA DGX Spark.

### Core Security Scripts
1. **secure-multiuser-setup.sh** - Main security hardening
2. **security-check.sh** - Health and audit tool
3. **vpn-protection-setup.sh** - VPN deployment

---

## Quick Start Paths

### Path 1: Basic Security
```bash
# 1. Setup base security
chmod +x *.sh
sudo ./secure-multiuser-setup.sh

# 2. Add users
sudo /usr/local/bin/add-user-with-quota.sh alice 10

# 3. Verify
sudo ./security-check.sh
```

### Path 2: Security + VPN
```bash
# 1. Run base security first
sudo ./secure-multiuser-setup.sh

# 2. Setup VPN (choose Tailscale for easiest)
sudo ./vpn-protection-setup.sh
# Select option 2 (Tailscale)

# 3. Restrict SSH to VPN only
sudo ufw delete allow 2222/tcp
sudo ufw allow from 100.64.0.0/10 to any port 2222

# 4. Test and verify
sudo ./security-check.sh
```

### Path 3: Maximum Security
```bash
# 1. Base security
sudo ./secure-multiuser-setup.sh

# 2. Advanced VPN protection
sudo ./vpn-protection-setup.sh
# Select option 4 (Advanced)

# 3. Configure monitoring
# Setup email alerts in fail2ban
# Enable weekly security reports

# 4. Test all layers
sudo ./security-check.sh
```

---

## By Use Case

### Home Lab / Learning
**Recommended:**
- Basic security setup
- Tailscale VPN (easiest)
- Weekly security checks

**Files to focus on:**
- QUICK-START.md
- vpn-protection-setup.sh (option 2)

### Small Business / Team Server
**Recommended:**
- Full security hardening
- WireGuard VPN (more control)
- Daily monitoring
- User quotas

**Files to focus on:**
- README.md
- SECURITY-GUIDE.md
- VPN-PROTECTION-GUIDE.md

### High-Security / Production
**Recommended:**
- Maximum security setup
- Multiple VPN options
- Port knocking
- GeoIP blocking
- Comprehensive auditing

**Files to focus on:**
- All documentation
- Regular security audits
- Custom configurations

### NVIDIA DGX Spark
**Recommended:**
- Modified security script
- Tailscale VPN (NAT-friendly)
- Preserve NVIDIA stack
- Use DGX Dashboard for updates

**Special notes:**
- Comment out automatic updates section
- Don't disable NVIDIA services
- Test GPU access after setup

---

## Script Functions Overview

### secure-multiuser-setup.sh
**What it does:**
- ✅ System updates and essential packages
- ✅ Create admin user with sudo
- ✅ Configure disk quotas
- ✅ SSH hardening (port change, root disable)
- ✅ Firewall setup (UFW)
- ✅ Fail2ban installation
- ✅ Automatic security updates
- ✅ Kernel hardening
- ✅ PAM security
- ✅ Audit logging
- ✅ File permission hardening
- ✅ Rootkit detection

**Time:** 10-15 minutes  
**Requires:** Root access, internet

### security-check.sh
**What it does:**
- ✅ Check user accounts
- ✅ Verify SSH security
- ✅ Check firewall status
- ✅ Verify fail2ban
- ✅ Disk usage and quotas
- ✅ System resources
- ✅ Service status
- ✅ Security updates available
- ✅ Recent security events
- ✅ Network ports
- ✅ File integrity
- ✅ Process monitoring

**Time:** 1-2 minutes  
**Use:** Run weekly or when suspicious

### vpn-protection-setup.sh
**What it does:**
Install and configure:
- WireGuard VPN server
- Tailscale mesh VPN
- Port knocking
- GeoIP blocking
- Advanced protection

**Time:** 15-30 minutes  
**Requires:** Root access, public IP

---

## Security Layers

### Layer 1: Network
- UFW firewall with default-deny
- Rate limiting
- GeoIP blocking (optional)
- Non-standard SSH port

### Layer 2: VPN
- WireGuard or Tailscale
- Encrypted tunnels
- Key-based authentication
- Hidden services

### Layer 3: Access Control
- SSH hardening
- Root login disabled
- Key authentication
- Port knocking (optional)

### Layer 4: Intrusion Detection
- Fail2ban
- Automatic banning
- Log monitoring
- Alert system

### Layer 5: System Hardening
- Kernel parameters
- PAM security
- File permissions
- Service restrictions

### Layer 6: Monitoring
- Audit logging
- Rootkit detection
- Security checks
- Access tracking

### Layer 7: Updates
- Automatic security patches
- Kernel updates
- Package management
- Vulnerability scanning

---

## Quick Help Commands

```bash
# Security status
sudo ./security-check.sh

# View active connections
sudo wg show              # WireGuard
sudo tailscale status     # Tailscale

# Check logs
sudo tail -f /var/log/auth.log
sudo journalctl -u ssh -f

# Firewall status
sudo ufw status verbose

# Fail2ban status
sudo fail2ban-client status sshd

# Who's logged in
who
w

# System resources
htop
df -h
```

---

## 🔄 Regular Maintenance

### Daily (5 minutes)
```bash
# Quick check
sudo ./security-check.sh | grep -i fail

# Check VPN
sudo wg show  # or: sudo tailscale status

# Review logs
sudo tail -50 /var/log/auth.log
```

### Weekly (15 minutes)
```bash
# Full security check
sudo ./security-check.sh > security-report.txt

# Review users
sudo repquota -a

# Check for updates
sudo apt update && sudo apt list --upgradable
```

### Monthly (30 minutes)
```bash
# Security audit
sudo lynis audit system

# Review firewall
sudo ufw status numbered

# Check rootkits
sudo rkhunter --check

# Review user accounts
sudo ./admin-menu.sh  # Option 3
```

### Quarterly (1 hour)
```bash
# Full system review
# - Review all users and permissions
# - Update documentation
# - Test backup/restore
# - Review incident response plan
# - Check security policies
```

---

## Additional Resources

### Official Documentation
- Ubuntu Security: https://ubuntu.com/security
- WireGuard: https://www.wireguard.com/
- Tailscale: https://tailscale.com/kb/
- UFW: https://help.ubuntu.com/community/UFW

### Security Standards
- CIS Benchmarks: https://www.cisecurity.org/cis-benchmarks/
- NIST: https://www.nist.gov/cybersecurity
- OWASP: https://owasp.org/

### Tools
- Lynis: https://cisofy.com/lynis/
- Fail2ban: https://www.fail2ban.org/
- rkhunter: http://rkhunter.sourceforge.net/

---

## 🎉 You're Ready!

You now have everything you need to:
- Secure your Ubuntu server
- Setup VPN protection
- Manage multiple users
- Monitor security
- Respond to incidents

**Remember:** Security is a journey, not a destination. Keep learning, keep improving, and stay vigilant!

---

**Last Updated:** November 2024  
**Version:** 1.0  
**Toolkit by:** Security-focused Linux administrators  
**License:** Free to use and modify
