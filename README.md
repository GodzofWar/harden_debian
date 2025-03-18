# Debian Linux Security Hardening Guide

## Introduction

This guide accompanies the Debian Linux Hardening Script and provides an overview of the security measures implemented. The script automates the application of security best practices to harden a Debian Linux system against common threats and vulnerabilities.

## Script Overview

The hardening script applies multiple layers of security to your Debian system:

1. System updates and security package installation
2. SSH access restriction and hardening
3. Firewall configuration
4. Password and authentication policy enforcement
5. System security limits and kernel parameter hardening
6. Service restrictions and auditing setup

## Key Security Features

### SSH Access Restriction

The script restricts SSH access to only specified IP addresses. This significantly reduces the attack surface by ensuring that only authorized networks can attempt SSH connections.

```bash
# Configure in the script:
SSH_WHITELIST_IPS=(
    "1.2.3.4"
    "5.6.7.8"
    # Add more IPs here if needed
)
```

The script implements this restriction through:
- SSH configuration (`AllowUsers` directive)
- TCP Wrappers (`hosts.allow` and `hosts.deny`)

### System Update and Security Packages

The script ensures your system is up-to-date and installs essential security tools:

- `ufw` - Uncomplicated Firewall
- `fail2ban` - Brute force attack prevention
- `unattended-upgrades` - Automatic security updates
- `rkhunter` & `chkrootkit` - Rootkit detection
- `lynis` - Security auditing tool
- `auditd` - System activity logging
- `apparmor` - Mandatory access control

### Firewall Configuration

A properly configured firewall is essential for system security:

- Default deny policy for incoming connections
- Default allow policy for outgoing connections
- SSH access allowed on the standard port (22/tcp)

### SSH Hardening

Beyond IP restrictions, SSH is hardened with several security configurations:

- Key-based authentication only
- Root login restricted to key authentication
- X11 forwarding disabled
- Maximum authentication attempts limited
- Client timeouts configured

### Password Policy Enhancement

Strong password policies are enforced through:

- Minimum password length (12 characters)
- Password complexity requirements (uppercase, lowercase, numbers, symbols)
- Password aging policies
- Removal of null password allowances

### System Security Limits

Resource limits are configured to prevent denial of service attacks:

- Core dump restrictions
- Maximum user process limits
- Open file limits

### Kernel Security Parameters

The script configures multiple kernel security parameters through sysctl:

- IP spoofing protection
- SYN flood protection
- ICMP broadcast request ignoring
- Source routing disabling
- ICMP redirect blocking
- Address Space Layout Randomization (ASLR)

### Service Restrictions

Unnecessary services are disabled to reduce the attack surface:

- Avahi daemon
- CUPS printing service
- DHCP server
- NFS server
- RPC bind
- SNMP daemon
- Telnet and TFTP services

### Filesystem Security

Mounting of uncommon filesystems is disabled to prevent potential exploits:

- cramfs, freevxfs, jffs2
- hfs, hfsplus
- squashfs, udf
- fat, vfat
- nfs, nfsv3, nfsv4

### System Auditing

Comprehensive auditing is configured to track:

- Authentication events
- File system mounts
- Configuration file changes
- Network configuration changes
- Privileged command execution
- Failed access attempts

## Usage Instructions

### Prerequisites

- Debian-based Linux system (Debian, Ubuntu, etc.)
- Root/sudo access
- System backup (recommended before applying)

### Configuration

Before running the script, review and modify the `SSH_WHITELIST_IPS` array at the top of the script to include the IP addresses that should have SSH access.

### Execution

1. Make the script executable:
   ```bash
   chmod +x debian_hardening.sh
   ```

2. Run the script as root:
   ```bash
   sudo ./debian_hardening.sh
   ```

3. Review the confirmation message and press 'y' to proceed.

### Post-Hardening Actions

After the script completes:

1. Reboot the system to ensure all changes take effect:
   ```bash
   sudo reboot
   ```

2. Run a security audit using Lynis:
   ```bash
   sudo lynis audit system
   ```

3. Review the audit report and address any remaining issues.

4. Check that SSH access works from your whitelisted IP addresses.

## Security Measures Not Covered

While this script provides comprehensive hardening, consider these additional security measures:

1. Full disk encryption
2. Two-factor authentication
3. Intrusion detection systems (IDS)
4. File integrity monitoring
5. Regular security audits and penetration testing
6. User security awareness training

## Troubleshooting

### SSH Access Issues

If you're locked out from SSH:

1. Access the system directly through the console
2. Check the IP whitelist in `/etc/ssh/sshd_config` and `/etc/hosts.allow`
3. Temporarily modify these files to allow your IP
4. Restart the SSH service:
   ```bash
   systemctl restart ssh
   ```

### Firewall Issues

If services are blocked unexpectedly:

1. Check UFW status:
   ```bash
   ufw status
   ```

2. Add rules for necessary services:
   ```bash
   ufw allow <port/service>
   ```

## Maintenance

### Regular Updates

Continue to update your system regularly:
```bash
apt update && apt upgrade -y
```

### Audit Log Review

Regularly review the audit logs:
```bash
ausearch -k auth_changes
ausearch -k network_changes
ausearch -k privileged
```

### Security Testing

Periodically test your security:
```bash
lynis audit system
rkhunter --check
chkrootkit
```

## Conclusion

This hardening script provides a solid foundation for securing your Debian Linux system. Remember that security is an ongoing process that requires regular updates, monitoring, and review of security policies.
