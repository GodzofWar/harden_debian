#!/bin/bash
#
# Debian Linux Hardening Script
# This script implements various security measures to harden a Debian Linux system
# Usage: sudo bash debian_hardening.sh
#

# ==========================================================
# CONFIGURATION - Edit these settings before running
# ==========================================================

# Define IP addresses to whitelist for SSH access
# Add or remove IPs as needed
SSH_WHITELIST_IPS=(
    # Add more IPs here if needed
    # "192.168.1.100"
    # "10.0.0.50"
)

# ==========================================================
# Script begins below - No need to modify unless customizing
# ==========================================================

# Ensure script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root" >&2
    exit 1
fi

# Function to display section headers
print_section() {
    echo "================================================================="
    echo "  $1"
    echo "================================================================="
}

# Function to restrict SSH access to specific IP addresses
restrict_ssh_access() {
    print_section "Restricting SSH Access to Specified IPs"
    
    local ip_list=("$@")
    
    # Check if any IPs were provided
    if [ ${#ip_list[@]} -eq 0 ]; then
        echo "No IP addresses specified in SSH_WHITELIST_IPS. SSH access will not be restricted."
        return 1
    fi
    
    # Backup sshd_config
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%Y%m%d-%H%M%S)
    
    # Remove any existing AllowUsers entries to avoid duplicates
    sed -i '/^AllowUsers/d' /etc/ssh/sshd_config
    
    # Create a new AllowUsers line with the specified IPs
    echo -n "AllowUsers " >> /etc/ssh/sshd_config
    
    # Add each IP to the AllowUsers line
    for ip in "${ip_list[@]}"; do
        echo -n "root@$ip " >> /etc/ssh/sshd_config
    done
    
    # Add the line break
    echo "" >> /etc/ssh/sshd_config
    
    # Configure sshd to only listen on specific addresses using TCP wrappers
    echo "sshd: ALL" > /etc/hosts.deny
    echo -n "sshd: " > /etc/hosts.allow
    
    for ip in "${ip_list[@]}"; do
        echo -n "$ip " >> /etc/hosts.allow
    done
    echo "" >> /etc/hosts.allow
    
    # Restart SSH service to apply changes
    systemctl restart ssh
    
    echo "SSH access restricted to the following IPs:"
    for ip in "${ip_list[@]}"; do
        echo "- $ip"
    done
}

# Update system and install security packages
update_system() {
    print_section "Updating System and Installing Security Packages"
    
    apt update
    apt upgrade -y
    
    # Install essential security packages
    apt install -y \
        ufw \
        fail2ban \
        unattended-upgrades \
        apt-listchanges \
        rkhunter \
        chkrootkit \
        lynis \
        auditd \
        libpam-pwquality \
        sudo \
        apparmor \
        apparmor-profiles \
        apparmor-utils
    
    # Configure unattended-upgrades
    echo 'APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";' > /etc/apt/apt.conf.d/20auto-upgrades
    
    echo "System updated and security packages installed."
}

# Configure firewall
configure_firewall() {
    print_section "Configuring Firewall (UFW)"
    
    # Reset UFW to default
    ufw --force reset
    
    # Set default policies
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow SSH (modify if you use a different port)
    ufw allow 22/tcp
    
    # Enable UFW
    ufw --force enable
    
    echo "UFW firewall configured and enabled."
}

# Harden SSH configuration
harden_ssh() {
    print_section "Hardening SSH Configuration"
    
    # Backup sshd_config
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%Y%m%d-%H%M%S)
    
    # Configure secure SSH settings
    sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
    sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    sed -i 's/^#\?X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config
    sed -i 's/^#\?MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config
    sed -i 's/^#\?ClientAliveInterval.*/ClientAliveInterval 300/' /etc/ssh/sshd_config
    sed -i 's/^#\?ClientAliveCountMax.*/ClientAliveCountMax 2/' /etc/ssh/sshd_config
    sed -i 's/^#\?PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config
    
    # Add or ensure Protocol 2 is set
    if grep -q "^Protocol" /etc/ssh/sshd_config; then
        sed -i 's/^Protocol.*/Protocol 2/' /etc/ssh/sshd_config
    else
        echo "Protocol 2" >> /etc/ssh/sshd_config
    fi
    
    # Restart SSH service
    systemctl restart ssh
    
    echo "SSH configuration hardened."
}

# Configure system security limits
configure_security_limits() {
    print_section "Configuring System Security Limits"
    
    # Backup limits.conf
    cp /etc/security/limits.conf /etc/security/limits.conf.backup.$(date +%Y%m%d-%H%M%S)
    
    # Add security limits
    cat << EOF >> /etc/security/limits.conf
# Core dumps restriction
* hard core 0
* soft core 0

# Max user processes
* hard nproc 10000
* soft nproc 1000

# Open file limits
* hard nofile 65535
* soft nofile 4096
EOF
    
    echo "System security limits configured."
}

# Configure password policies
configure_password_policies() {
    print_section "Configuring Password Policies"
    
    # Backup pwquality.conf
    cp /etc/security/pwquality.conf /etc/security/pwquality.conf.backup.$(date +%Y%m%d-%H%M%S)
    
    # Configure password quality requirements
    sed -i 's/^# minlen =.*/minlen = 12/' /etc/security/pwquality.conf
    sed -i 's/^# minclass =.*/minclass = 4/' /etc/security/pwquality.conf
    sed -i 's/^# dcredit =.*/dcredit = -1/' /etc/security/pwquality.conf
    sed -i 's/^# ucredit =.*/ucredit = -1/' /etc/security/pwquality.conf
    sed -i 's/^# ocredit =.*/ocredit = -1/' /etc/security/pwquality.conf
    sed -i 's/^# lcredit =.*/lcredit = -1/' /etc/security/pwquality.conf
    
    # Configure PAM
    sed -i 's/nullok_secure//' /etc/pam.d/common-auth
    
    # Configure login.defs
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
    sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs
    
    echo "Password policies configured."
}

# Secure shared memory
secure_shared_memory() {
    print_section "Securing Shared Memory"
    
    # Add entry to fstab if not already present
    if ! grep -q "tmpfs /run/shm" /etc/fstab; then
        echo "tmpfs /run/shm tmpfs defaults,noexec,nosuid,nodev 0 0" >> /etc/fstab
    fi
    
    echo "Shared memory secured."
}

# Configure fail2ban
configure_fail2ban() {
    print_section "Configuring Fail2Ban"
    
    # Create a basic jail.local configuration
    cat << EOF > /etc/fail2ban/jail.local
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
EOF
    
    # Restart fail2ban
    systemctl restart fail2ban
    
    echo "Fail2Ban configured."
}

# Disable unused services
disable_unused_services() {
    print_section "Disabling Unused Services"
    
    # List of common services to disable (modify as needed)
    SERVICES_TO_DISABLE=(
        "avahi-daemon"
        "cups"
        "isc-dhcp-server"
        "nfs-server"
        "rpcbind"
        "rsync"
        "snmpd"
        "telnet"
        "tftp"
    )
    
    for service in "${SERVICES_TO_DISABLE[@]}"; do
        if systemctl is-active --quiet "$service"; then
            systemctl stop "$service"
            systemctl disable "$service"
            echo "Service $service stopped and disabled."
        else
            echo "Service $service is already disabled or not installed."
        fi
    done
    
    echo "Unused services disabled."
}

# Secure sysctl parameters
secure_sysctl() {
    print_section "Configuring Secure Sysctl Parameters"
    
    # Create a custom security sysctl configuration
    cat << EOF > /etc/sysctl.d/99-security.conf
# IP Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP broadcast requests
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Ignore send redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Block SYN attacks
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# Log Martians
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Ignore Directed pings
net.ipv4.icmp_echo_ignore_all = 0

# Protect against kernel pointer leaks
kernel.kptr_restrict = 2

# Restrict dmesg access
kernel.dmesg_restrict = 1

# Restrict access to kernel logs
kernel.perf_event_paranoid = 3

# Protect against the exploitation of ASLR weaknesses
kernel.randomize_va_space = 2

# Restrict core dumps
fs.suid_dumpable = 0

# Disable IPv6 if not needed
#net.ipv6.conf.all.disable_ipv6 = 1
#net.ipv6.conf.default.disable_ipv6 = 1
#net.ipv6.conf.lo.disable_ipv6 = 1
EOF
    
    # Apply the settings
    sysctl -p /etc/sysctl.d/99-security.conf
    
    echo "Secure sysctl parameters configured."
}

# Audit and restrict SUID/SGID binaries
restrict_suid_sgid() {
    print_section "Auditing and Restricting SUID/SGID Binaries"
    
    # Create a list of SUID/SGID files
    find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -la {} \; > /root/suid_sgid_files.txt 2>/dev/null
    
    echo "SUID/SGID files have been listed in /root/suid_sgid_files.txt"
    echo "Please review this list and manually restrict unnecessary SUID/SGID permissions."
}

# Configure audit daemon
configure_auditd() {
    print_section "Configuring Audit Daemon"
    
    # Backup audit rules
    cp /etc/audit/audit.rules /etc/audit/audit.rules.backup.$(date +%Y%m%d-%H%M%S)
    
    # Create custom audit rules
    cat << EOF > /etc/audit/rules.d/audit.rules
# Delete all existing rules
-D

# Set buffer size
-b 8192

# Failure mode: 1=silent, 2=printk
-f 1

# Monitor file system mounts
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mount
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mount

# Monitor changes to authentication configuration files
-w /etc/pam.d/ -p wa -k auth_changes
-w /etc/nsswitch.conf -p wa -k auth_changes
-w /etc/shadow -p wa -k auth_changes
-w /etc/passwd -p wa -k auth_changes
-w /etc/group -p wa -k auth_changes
-w /etc/gshadow -p wa -k auth_changes
-w /etc/security/ -p wa -k auth_changes

# Monitor changes to network configuration
-w /etc/network/ -p wa -k network_changes
-w /etc/hosts -p wa -k network_changes
-w /etc/sysconfig/network -p wa -k network_changes

# Monitor changes to system configuration files
-w /etc/sudoers -p wa -k sudoers_changes
-w /etc/sudoers.d/ -p wa -k sudoers_changes
-w /etc/ssh/sshd_config -p wa -k sshd_config

# Monitor privileged command execution
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

# Monitor successful/unsuccessful modifications to sudoers files
-w /etc/sudoers -p wa -k actions
-w /etc/sudoers.d/ -p wa -k actions

# Monitor admin commands
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules

# Monitor system calls
-a always,exit -F arch=b64 -S execve -k exec
-a always,exit -F arch=b32 -S execve -k exec

# Monitor unsuccessful authorization attempts
-a always,exit -F arch=b64 -S open -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S open -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S open -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S open -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access

# Make the configuration immutable
-e 2
EOF
    
    # Restart auditd
    service auditd restart
    
    echo "Audit daemon configured."
}

# Disable unused filesystems
disable_unused_filesystems() {
    print_section "Disabling Unused Filesystems"
    
    # Create a configuration file to disable mounting of uncommon filesystems
    cat << EOF > /etc/modprobe.d/disable-filesystems.conf
# Disable mounting of uncommon filesystems
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
install fat /bin/true
install vfat /bin/true
install nfs /bin/true
install nfsv3 /bin/true
install nfsv4 /bin/true
install gfs2 /bin/true
EOF
    
    echo "Unused filesystems disabled."
}

# Main function
main() {
    echo "==================================================================="
    echo "            Debian Linux Hardening Script                          "
    echo "==================================================================="
    echo "This script will implement various security measures to harden your"
    echo "Debian Linux system. Please ensure you have a backup before proceeding."
    echo "==================================================================="
    echo ""
    
    # Display IP whitelist
    echo "SSH access will be restricted to the following IPs:"
    for ip in "${SSH_WHITELIST_IPS[@]}"; do
        echo "- $ip"
    done
    echo ""
    
    # Get confirmation
    read -p "Do you want to proceed with system hardening? (y/n): " confirm
    
    if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
        echo "Operation cancelled."
        exit 0
    fi
    
    # Run hardening functions
    update_system
    configure_firewall
    harden_ssh
    configure_security_limits
    configure_password_policies
    secure_shared_memory
    configure_fail2ban
    disable_unused_services
    secure_sysctl
    restrict_suid_sgid
    configure_auditd
    disable_unused_filesystems
    
    # Restrict SSH access to the IPs defined in the script
    restrict_ssh_access "${SSH_WHITELIST_IPS[@]}"
    
    echo ""
    print_section "System Hardening Completed"
    echo "System hardening procedures have been applied."
    echo "Please review any backup files created and reboot the system to ensure all changes take effect."
    echo "Run 'lynis audit system' to perform a security audit of your system."
    echo "==================================================================="
}

# Run the main function
main
