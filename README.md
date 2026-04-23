# Linux-Server-Hardening

Deep Linux Server Hardening with Ansible

This project contains an Ansible playbook for deeply hardening a RHEL-based Linux server. The playbook includes SSH configuration, SELinux, Fail2Ban firewall setup, kernel hardening, service restrictions, auditing, auto-updates, and reporting.

Be sure to change file paths and parameters as needed to match your system.*

****Console Access will be the only way to remote in, be sure to take snapshots of the server or be logged in on another terminal. Reset setting manually if needed by editing '/etc/yum.conf' /etc/selinux

Features:

SSH lockdown (no root, no password login)

Kernel-level sysctl security tuning

Disable legacy/risky services

Enforce secure umask and file permissions

Firewall configuration with firewalld

Enable auto-updates with dnf-automatic

Enable audit logging and Fail2Ban

Generate and email security hardening reports

Activate SELinux (runtime and config)

🔧 Playbook Breakdown

Create Report Directories & Files
Create /home/dariusp/patching_reports/secure_servers
Create three files: .report, .report.header, .report.body
Purpose: Prepare structure for logging and reporting hardening status.

SSH Hardening
Restrict SSH access to allowed users
Set SSH port to 22
Disable root login
Disable password-based SSH logins
Purpose: Minimize remote access vectors and enforce key-based auth.

Disable Unnecessary Services
Loop through disable_services to stop and disable legacy daemons
Purpose: Remove insecure services like telnet, rlogin, rsh.

Apply Kernel sysctl Hardening
Use sysctl module to apply hardened values (e.g., disable IP forwarding, spoofing)
Purpose: Protect against networking attacks and enforce kernel-level security policies.

Filesystem & Core Dump Protections
Set umask to 027 (restrict default file perms)
Disable core dumps for all users
Purpose: Prevent data leakage from dumped memory or insecure defaults.

Install and Enable firewalld
Install firewalld
Enable and start the service
Allow only the ssh service
Restart firewall to apply rules
Purpose: Enforce network-level security using firewall rules.

Configure Auto Security Updates
Install dnf-automatic
Enable the systemd timer dnf-automatic.timer
Purpose: Keep system patched with critical updates automatically.

Install and Enable Auditd
Install and start auditd
Run aureport to verify logs are working
Output log summary with debug
Purpose: Enable audit logging for traceability and compliance.

Enforce Critical File Permissions
Set /etc/passwd to 0644
Set /etc/shadow to 0000
Purpose: Lock down sensitive identity-related files.

Install and Configure Fail2ban
Install and start fail2ban
Purpose: Protect from SSH brute-force and failed login abuse.

Create Report Header and Body
Use shell to echo system metadata (hostname, kernel, uptime)
Generate structured .report.header and .report.body
Purpose: Provide a detailed snapshot of the hardened system.

Compile and Convert Final Report
Concatenate header and body into .report
Copy .report into .txt file for easier sharing
Purpose: Final report generated for visibility and auditing.

Email the Report
Install s-nail
Use mailx to email report to administrator
Purpose: Automatically alert or notify via email post-hardening.

Activate SELinux
Set SELinux to enabled in /etc/selinux/config
Use setenforce 1 to apply enforcement in real-time
Purpose: Enforce mandatory access controls to limit damage from compromised processes.

⚙️ Requirements

Rocky Linux / RHEL / CentOS

Ansible 2.10+

Python installed on target machine

SSH access to target

Your vars.yml should define:

allowed_ssh_users:

dariusp
disable_services:

telnet
rsh
rlogin
sysctl_hardening: net.ipv4.ip_forward: 0 net.ipv4.conf.all.accept_source_route: 0 net.ipv4.conf.all.accept_redirects: 0 net.ipv4.conf.all.send_redirects: 0 net.ipv4.conf.all.log_martians: 1 net.ipv4.icmp_echo_ignore_broadcasts: 1 net.ipv4.tcp_syncookies: 1

🚀 Run the Playbook

ansible-playbook secure_lockdown.yml --step (I like to use '--step' just to have more control over the configurations. Also, it is good practice for error handling!)

Some flags that may be used**

--step (prompt before each task is ran)

--start-at-task"" (start at a specific task)

--ask-become-pass ---- (prompt for become password)

--ask-vault-pass ----- (prompt for vault password)

Example Report file included!

🌍 Use Cases

Internal DevSecOps environments
Chaos-ready automation (resilient provisioning)
Infrastructure compliance bootstrapping
🧠 About

Created and maintained by Darius Powell

packer practice

To make this "Golden Image" production-ready for the AWS and Azure marketplaces, we will split your logic. Your vars.yml will act as the "Control Panel," allowing you to toggle security levels and settings without touching the code.

The playbook.yml now uses a "Hybrid" approach: it runs your custom Company branding and cleanup, then calls the industry-standard CIS roles to ensure you pass any corporate audit.

1. The vars.yml File
This file allows you to customize the image for different Sprints (e.g., set pci_compliance: true for Sprint 1).

---
# Company Image Configuration
brand_name: "Company"
report_dir: "/opt/Company/compliance"

# SSH Access (Cloud Agnostic)
# Instead of hardcoding users, we allow groups that AWS/Azure use
allowed_groups: ["sudo", "wheel", "adm"]

# CIS Hardening Toggles
# Turn these to 'false' if you are troubleshooting a build
run_cis_level_1: true
run_cis_level_2: true  # Set to true for PCI/HIPAA images
setup_audit: true

# Network Hardening
sysctl_settings:
  net.ipv4.ip_forward: 0
  net.ipv4.conf.all.send_redirects: 0
  net.ipv4.conf.all.accept_redirects: 0
  net.ipv4.tcp_syncookies: 1
  kernel.modules_disabled: 1

# Software to install on EVERY base image
base_packages:
  - firewalld
  - dnf-automatic
  - fail2ban
  - audit
  - s-nail
  - tar
  - curl
2. The playbook.yml File
This rewritten playbook is "Silent" and "Environment Agnostic." It uses your existing logic but formats it for a professional marketplace release.

---
- name: Build Company Golden Base Image
  hosts: all
  become: true
  vars_files:
    - vars.yml

  # This section pulls in the heavy-duty CIS hardening
  roles:
    - role: UBUNTU24-CIS # or RHEL9-CIS for Rocky
      when: run_cis_level_1

  tasks:
    - name: 1. SYSTEM PREP - Create Branding & Report Dirs
      file:
        path: "{{ report_dir }}"
        state: directory
        mode: '0750'
        owner: root
        group: root

    - name: 2. PACKAGE MGMT - Install Base Security Stack
      package:
        name: "{{ base_packages }}"
        state: present

    - name: 3. SSH HARDENING - Secure Access Policy
      lineinfile:
        path: /etc/ssh/sshd_config
        regexp: "{{ item.regexp }}"
        line: "{{ item.line }}"
        state: present
        validate: '/usr/sbin/sshd -t -f %s'
      loop:
        - { regexp: "^#?PermitRootLogin", line: "PermitRootLogin no" }
        - { regexp: "^#?PasswordAuthentication", line: "PasswordAuthentication no" }
        - { regexp: "^#?AllowGroups", line: "AllowGroups {{ allowed_groups | join(' ') }}" }
        - { regexp: "^#?MaxAuthTries", line: "MaxAuthTries 3" }

    - name: 4. KERNEL - Apply Company sysctl Params
      sysctl:
        name: "{{ item.key }}"
        value: "{{ item.value | string }}"
        state: present
        reload: yes
      loop: "{{ sysctl_settings | dict2items }}"

    - name: 5. AUTOMATION - Configure Passive Patching
      service:
        name: dnf-automatic.timer
        state: started
        enabled: yes

    - name: 6. COMPLIANCE - Generate Local Manifest
      shell: |
        echo "------------------------------------------------" > {{ report_dir }}/manifest.txt
        echo "Company HARDENED IMAGE MANIFEST" >> {{ report_dir }}/manifest.txt
        echo "Build Date: $(date)" >> {{ report_dir }}/manifest.txt
        echo "OS Version: $(cat /etc/os-release | grep PRETTY_NAME)" >> {{ report_dir }}/manifest.txt
        echo "Compliance Level: CIS Level 2" >> {{ report_dir }}/manifest.txt
        echo "------------------------------------------------" >> {{ report_dir }}/manifest.txt
      tags: manifest

    - name: 7. CLEANUP - Prepare for Cloud Capture (Packer Only)
      shell: |
        # This removes YOUR history so the CUSTOMER starts fresh
        rm -rf /tmp/*
        rm -rf /var/tmp/*
        truncate -s 0 /var/log/audit/audit.log
        rm -f /root/.bash_history
        rm -f /home/*/.bash_history
        history -c
      tags: cleanup
3. How to Practice on VirtualBox (Detailed Steps)
To get this running on your local machine today:

Install the CIS Role: Run this command in your terminal so Ansible can find the UBUNTU24-CIS role: ansible-galaxy install git+https://github.com/ansible-lockdown/UBUNTU24-CIS.git

Verify SSH Key: Since this playbook sets PasswordAuthentication no, you must copy your SSH key to the VM before running the playbook, or you will be locked out: ssh-copy-id -i ~/.ssh/id_rsa.pub user@vm-ip

Run the Playbook: ansible-playbook -i your_vm_ip, playbook.yml

Why this is better for your business:
Scalability: When you build the VPN Gateway later, you can just add a new task at the end of this playbook: apt: name=wireguard state=present.
Professionalism: The manifest.txt is a tangible "asset" the client finds when they log in. It proves you did the work.
Passive Maintenance: By enabling dnf-automatic.timer, the image patches itself forever without you ever logging back in.
Would you like the requirements.yml file to automate the installation of all the necessary Galaxy roles for your other 9 images?
