# Complete Ubuntu Security & VPN Toolkit

## What's Included

This is a complete security toolkit for Ubuntu servers with public IP addresses, especially designed for multi-user environments like NVIDIA DGX Spark.

### Core Security Scripts
1. **secure-multiuser-setup.sh** - Main security hardening
2. **security-check.sh** - Health and audit tool
3. **admin-menu.sh** - Interactive administration
4. **vpn-protection-setup.sh** - VPN deployment

### Documentation
5. **README.md** - Main overview and quick reference
6. **QUICK-START.md** - Fast setup with visual guides
7. **SECURITY-GUIDE.md** - Detailed security procedures
8. **VPN-PROTECTION-GUIDE.md** - Complete VPN guide
9. **VPN-QUICK-REFERENCE.md** - VPN commands cheat sheet
10. **INDEX.md** - This file

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

## Documentation Guide

### For First-Time Users
**Start here:** QUICK-START.md
- Visual diagrams
- Step-by-step setup
- Common scenarios

### For System Administrators
**Read:** README.md → SECURITY-GUIDE.md
- Complete feature reference
- Best practices
- Maintenance procedures

### For VPN Setup
**Read:** VPN-PROTECTION-GUIDE.md
- Compare VPN solutions
- Step-by-step for each option
- Troubleshooting guide

**Keep handy:** VPN-QUICK-REFERENCE.md
- Common commands
- Quick troubleshooting
- Architecture diagrams

---

## 🎯 By Use Case

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

## 🛠️ Script Functions Overview

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

### admin-menu.sh
**What it does:**
Interactive menu for:
- User management (add/remove/quota)
- SSH and fail2ban monitoring
- Firewall management
- System monitoring
- Log viewing
- Maintenance tasks

**Time:** N/A (interactive)  
**Use:** Daily administration

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

## 🔐 Security Layers

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

## 📊 Feature Matrix

| Feature | Script | Time | Difficulty | Priority |
|---------|--------|------|------------|----------|
| **SSH Hardening** | secure-multiuser | 5min | Easy | High |
| **Firewall (UFW)** | secure-multiuser | 2min | Easy | High |
| **Fail2ban** | secure-multiuser | 3min | Easy | High |
| **User Quotas** | secure-multiuser | 5min | Medium | Medium |
| **Auto Updates** | secure-multiuser | 2min | Easy | High |
| **Audit Logging** | secure-multiuser | 3min | Medium | Medium |
| **WireGuard VPN** | vpn-protection | 15min | Medium | High |
| **Tailscale VPN** | vpn-protection | 10min | Easy | High |
| **Port Knocking** | vpn-protection | 5min | Medium | Low |
| **GeoIP Block** | vpn-protection | 10min | Medium | Low |

---

## 🎓 Learning Path

### Week 1: Basics
- [ ] Understand security concepts
- [ ] Run secure-multiuser-setup.sh
- [ ] Add/remove test users
- [ ] Run security-check.sh daily
- [ ] Read README.md and QUICK-START.md

### Week 2: VPN
- [ ] Choose VPN solution
- [ ] Setup VPN (Tailscale recommended)
- [ ] Configure clients
- [ ] Test connectivity
- [ ] Read VPN-PROTECTION-GUIDE.md

### Week 3: Hardening
- [ ] Restrict SSH to VPN only
- [ ] Setup port knocking
- [ ] Configure email alerts
- [ ] Test fail2ban
- [ ] Read SECURITY-GUIDE.md

### Week 4: Operations
- [ ] Create maintenance schedule
- [ ] Document procedures
- [ ] Setup monitoring
- [ ] Practice incident response
- [ ] Regular security audits

---

## 🆘 Troubleshooting Index

### Can't SSH After Setup
**File:** QUICK-START.md → Troubleshooting  
**Quick fix:** Check SSH port changed to 2222

### VPN Not Connecting
**File:** VPN-QUICK-REFERENCE.md → Emergency  
**Quick fix:** Check firewall allows VPN port

### Locked Out
**File:** SECURITY-GUIDE.md → Incident Response  
**Quick fix:** Use cloud console or recovery mode

### Quota Issues
**File:** SECURITY-GUIDE.md → Troubleshooting  
**Quick fix:** Remount with quotas

### Performance Issues
**File:** README.md → Monitoring  
**Quick fix:** Run security-check.sh

---

## 📞 Quick Help Commands

```bash
# Security status
sudo ./security-check.sh

# Interactive admin
sudo ./admin-menu.sh

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

## 📦 File Download Priority

### Must Have
1. secure-multiuser-setup.sh
2. README.md
3. QUICK-START.md

### Highly Recommended
4. security-check.sh
5. vpn-protection-setup.sh
6. VPN-PROTECTION-GUIDE.md

### Nice to Have
7. admin-menu.sh
8. SECURITY-GUIDE.md
9. VPN-QUICK-REFERENCE.md
10. INDEX.md (this file)

---

## 🎯 Success Checklist

### After Initial Setup
- [ ] SSH works on new port
- [ ] Admin user created
- [ ] Firewall active
- [ ] Fail2ban running
- [ ] Security check passes
- [ ] Users can login
- [ ] Quotas enforced

### After VPN Setup
- [ ] VPN service running
- [ ] Can connect from device
- [ ] SSH works through VPN
- [ ] Firewall allows VPN
- [ ] Clients configured
- [ ] Backup of configs

### Production Ready
- [ ] SSH restricted to VPN
- [ ] Email alerts configured
- [ ] Monitoring active
- [ ] Documentation complete
- [ ] Backup strategy in place
- [ ] Team trained
- [ ] Incident response ready

---

## 💡 Pro Tips

1. **Always test in a VM first** if new to Linux administration
2. **Keep a second SSH session open** when making firewall changes
3. **Document everything** - future you will thank you
4. **Start simple** - add complexity as you learn
5. **Backup configs** before making changes
6. **Monitor logs** - they tell you what's happening
7. **Use VPN** - it's the best protection for public IPs
8. **Regular audits** - security is ongoing, not one-time
9. **Stay updated** - subscribe to security mailing lists
10. **Have a rollback plan** - always know how to undo changes

---

## 📚 Additional Resources

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
