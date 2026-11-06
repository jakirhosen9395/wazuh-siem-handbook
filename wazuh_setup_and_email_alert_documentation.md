# Wazuh 4.14.9 All-in-One Setup, Security Monitoring & Email Alert Runbook

This runbook documents the complete end-to-end deployment of **Wazuh v4.14.9** (Indexer, Manager, Filebeat, and Dashboard) and the **Wazuh Agent** on **Red Hat Enterprise Linux (RHEL) 9.8**, tailored for real-time command auditing, File Integrity Monitoring (FIM), SFTP transfer auditing, and SMTP email alerting.

---

## Project Implementation Status Overview

| Feature / Component | Status | Notes |
| :--- | :--- | :--- |
| **Wazuh All-in-One Server (v4.14.9)** | **Completed** | Deployed on RHEL 9.8 (`11.11.2.7`) with 99 GB root disk and 4 GB Swap. |
| **Wazuh Agent (`vnc-server` v4.14.9)** | **Completed** | Installed via standalone RPM and enrolled with `11.11.2.7`. |
| **Kernel `auditd` Command & User Tracking** | **Completed** | Tracks all `execve` commands (`auid >= 1000`), `/etc/passwd`, `/etc/shadow`, and `/etc/tigervnc`. |
| **Real-Time FIM (`whodata="yes"`)** | **Completed** | Monitors `/etc`, `/usr/bin`, `/usr/sbin`, `/boot`, `/home`, and `/root` with real-time kernel events. |
| **OpenSSH / SFTP Access & Verbose Logging** | **Completed** | Configured `internal-sftp -f AUTHPRIV -l INFO` and `sftp-allowed` / `sftp-denied` match groups. |
| **Custom PCRE2 SFTP Decoders & Rules** | **Completed** | Rules `100501`–`100506` active and verified via `wazuh-logtest` and live syslog injection. |
| **Postfix Gmail SMTP Relay & Email Alerts** | **Completed** | Configured with SASL App Password authentication; live email delivery verified (`status=sent`). |
| **5-in-10-Minute Brute-Force Email Rule** | **To Be Performed** | Documented in **Section 9** (includes suppressing single-failure email noise). |
| **TigerVNC, GUI & `eng-001`..`eng-004` Users** | **To Be Performed** | Scheduled after completing the Wazuh monitoring baseline. |

---

## 1. Wazuh Architecture and Server/Agent Roles

### Environment Topology

| Role | Hostname | IP Placeholder | OS Version | Installed Services / Daemons |
| :--- | :--- | :--- | :--- | :--- |
| **Wazuh All-in-One Server** | `wazuh-server` | `11.11.2.7` | RHEL 9.8 (`x86_64`) | `wazuh-indexer` (OpenSearch 2.19.6), `wazuh-manager` (v4.14.9), `filebeat` (v7.10.2), `wazuh-dashboard` (v4.14.9), `postfix`, `auditd` |
| **Monitored Agent Server** | `vnc-server` | `11.11.2.143` | RHEL 9.8 (`x86_64`) | `wazuh-agent` (v4.14.9), `auditd`, `sshd` (`internal-sftp`) |

### Network & Firewall Port Matrix

| Port | Protocol | Direction | Purpose |
| :--- | :--- | :--- | :--- |
| **443** | TCP | Admin IPs -> `wazuh-server` | Wazuh Dashboard Web UI (HTTPS) |
| **1514** | TCP | `vnc-server` -> `wazuh-server` | Wazuh Agent encrypted event stream (`wazuh-remoted`) |
| **1515** | TCP | `vnc-server` -> `wazuh-server` | Wazuh Agent enrollment (`wazuh-authd`) |
| **55000** | TCP | Localhost / Admin -> `wazuh-server` | Wazuh Server RESTful API (`wazuh-apid`) |
| **9200** | TCP | `127.0.0.1` (Localhost) | Wazuh Indexer REST API (OpenSearch) |
| **587** | TCP | `wazuh-server` -> `smtp.gmail.com` | Outbound Postfix STARTTLS email relay |

---

## 2. Prerequisites and System Preparation

### Hardware Specifications
* **CPU:** 4 vCPUs (Intel Xeon Platinum 8124M @ 3.00GHz)
* **RAM:** 8 GiB (`7421 MB` usable) + **4 GiB Swap file**
* **Disk:** **100 GB GP3 EBS Volume** (`99G` mounted on `/`).
  * *Lesson Learned:* Attempting the All-in-One installation on a 29 GB root volume without swap or pre-installed libraries caused `wazuh-dashboard` (286 MB RPM / 960 MB unpacked) to fail during package installation and trigger an automatic rollback.

### Step 1: Update OS Packages and Reboot
**Execute on:** `wazuh-server` (`11.11.2.7`) **and** `vnc-server` (`11.11.2.143`)

```bash
sudo dnf clean all
sudo dnf makecache
sudo dnf upgrade -y
sudo dnf needs-restarting -r || sudo reboot
```

**Validation:**
```bash
uname -r
# Expected output: 5.14.0-687.66.1.el9_8.x86_64 (or latest installed kernel)
```

### Step 2: Set Hostname, 4 GB Swap File, and Kernel Parameters
**Execute on:** `wazuh-server` (`11.11.2.7`)

```bash
# 1. Set system hostname
sudo hostnamectl set-hostname wazuh-server

# 2. Create and persist a 4 GB Swap file
sudo fallocate -l 4G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
grep -q '/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab

# 3. Configure kernel virtual memory map count for OpenSearch (wazuh-indexer)
cat << 'EOF' | sudo tee /etc/sysctl.d/99-wazuh.conf
vm.max_map_count=262144
vm.swappiness=10
EOF
sudo sysctl --system
```

**Validation:**
```bash
free -m
sysctl vm.max_map_count
```

### Step 3: Verify / Expand Root Partition Space (`100 GB`)
**Execute on:** `wazuh-server` (`11.11.2.7`)

```bash
df -h /
# If the EBS volume was expanded in AWS Console but the partition is still 29G, grow it online:
sudo dnf install -y cloud-utils-growpart
sudo growpart /dev/nvme0n1 4
sudo xfs_growfs /
```

### Step 4: Configure DNF Timeout Resiliency & Pre-Install OS Libraries
**Execute on:** `wazuh-server` (`11.11.2.7`)

Modify `/etc/dnf/dnf.conf` and install the shared libraries required by `wazuh-dashboard`, `wazuh-indexer`, and `wazuh-manager`:

```bash
grep -q '^timeout=' /etc/dnf/dnf.conf || echo -e "timeout=300\nretries=10\nminrate=1000" | sudo tee -a /etc/dnf/dnf.conf

sudo dnf install -y curl tar coreutils gnupg2 lsof libcap fontconfig nss openssl-libs policycoreutils-python-utils
```

### Step 5: Open Required Ports in `firewalld`
**Execute on:** `wazuh-server` (`11.11.2.7`)

```bash
if systemctl is-active --quiet firewalld; then
    sudo firewall-cmd --permanent --add-port={443/tcp,1514/tcp,1515/tcp,55000/tcp}
    sudo firewall-cmd --reload
fi
```

---

## 3. Wazuh Installation and Initial Configuration (Completed)

### Step 1: Run the Official Wazuh 4.14 All-in-One Installation Assistant
**Execute on:** `wazuh-server` (`11.11.2.7`)

```bash
cd ~
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
sudo bash ./wazuh-install.sh -a -i -v
```

When the script finishes, it outputs the access summary:
```text
INFO: --- Summary ---
INFO: You can access the web interface https://11.11.2.7:443
    User: admin
    Password: <WAZUH_ADMIN_PASSWORD>
INFO: Installation finished.
```

### Step 2: Back Up Credentials and Disable Repository Auto-Updates
**Execute on:** `wazuh-server` (`11.11.2.7`)

Back up `wazuh-install-files.tar` to `/root/` and disable `/etc/yum.repos.d/wazuh.repo` so routine `dnf upgrade` commands do not unintentionally upgrade Wazuh out of sync:

```bash
sudo cp ./wazuh-install-files.tar /root/wazuh-install-files-backup.tar
sudo chmod 600 /root/wazuh-install-files-backup.tar

sudo sed -i "s/^enabled=1/enabled=0/" /etc/yum.repos.d/wazuh.repo
```

**Validation:**
```bash
sudo systemctl status wazuh-indexer wazuh-manager filebeat wazuh-dashboard --no-pager
```

---

## 4. Wazuh Agent Installation and Registration (Completed)

### Selecting and Preparing a Monitored Agent Server
Any RHEL 9 server (such as `vnc-server` at `11.11.2.143`) that hosts user sessions, SSH/SFTP access, or critical engineering data should have `wazuh-agent` installed. The agent requires outbound TCP connectivity to `11.11.2.7` on ports **1514** and **1515**.

### Step 1: Verify Connectivity to the Wazuh Manager
**Execute on:** `vnc-server` (`11.11.2.143`)

```bash
timeout 3 bash -c "</dev/tcp/11.11.2.7/1514 && echo 'Port 1514 Open'"
timeout 3 bash -c "</dev/tcp/11.11.2.7/1515 && echo 'Port 1515 Open'"
```

### Step 2: Install and Register the Wazuh Agent via Direct RPM
**Execute on:** `vnc-server` (`11.11.2.143`)

Download the standalone `wazuh-agent-4.14.9-1.x86_64.rpm` package and pass `WAZUH_MANAGER` and `WAZUH_AGENT_NAME` directly to `rpm -ihv`:

```bash
sudo rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH

curl -o wazuh-agent-4.14.9-1.x86_64.rpm https://packages.wazuh.com/4.x/yum/wazuh-agent-4.14.9-1.x86_64.rpm && \
sudo WAZUH_MANAGER='11.11.2.7' WAZUH_AGENT_NAME='vnc-server' rpm -ihv wazuh-agent-4.14.9-1.x86_64.rpm

rm -f wazuh-agent-4.14.9-1.x86_64.rpm
```

### Step 3: Enable and Start `wazuh-agent`
**Execute on:** `vnc-server` (`11.11.2.143`)

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-agent
```

**Validation (on `wazuh-server`):**
```bash
sudo /var/ossec/bin/agent_control -l
```

---

## 5. Agent Configuration and Log Collection (Completed)

To capture every command executed by `ec2-user`, `root`, and VNC users (`eng-001`..`eng-004`), track user/group modifications, log all SFTP transfers/failures, and stream logs to `wazuh-server` within 1–5 seconds, configure both `auditd`, `sshd`, and the Wazuh Agent.

### Step 1: Configure Kernel `auditd` Rules on the Agent
**Execute on:** `vnc-server` (`11.11.2.143`)

Create `/etc/audit/rules.d/wazuh-full-monitoring.rules` (and ensure any older duplicate file such as `wazuh-command-audit.rules` is removed and `/etc/tigervnc` exists so `augenrules` loads cleanly):

```bash
sudo dnf install -y audit
sudo systemctl enable --now auditd

# Remove older duplicate rule files and pre-create /etc/tigervnc directory
sudo rm -f /etc/audit/rules.d/wazuh-command-audit.rules
sudo mkdir -p /etc/tigervnc
```

Create `/etc/audit/rules.d/wazuh-full-monitoring.rules`:
```bash
sudo tee /etc/audit/rules.d/wazuh-full-monitoring.rules << 'EOF'
## Clear existing rules and set high kernel buffer
-D
-b 8192

## 1. Track ALL commands run by ec2-user, VNC users, and sudo/root escalations (auid >= 1000)
-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=-1 -k audit-wazuh-c
-a always,exit -F arch=b32 -S execve -F auid>=1000 -F auid!=-1 -k audit-wazuh-c

## 2. Track Linux user, group, password, and VNC password changes
-w /etc/passwd -p wa -k user-modify
-w /etc/shadow -p wa -k user-modify
-w /etc/group -p wa -k user-modify
-w /etc/gshadow -p wa -k user-modify
-w /etc/tigervnc/ -p wa -k vnc-config-modify
EOF

sudo augenrules --load
```

**Validation:**
```bash
sudo auditctl -l
```

### Step 2: Configure Kernel `auditd` Rules on the Wazuh Server
**Execute on:** `wazuh-server` (`11.11.2.7`)

```bash
sudo tee /etc/audit/rules.d/wazuh-command-audit.rules << 'EOF'
-D
-b 8192
-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=-1 -k audit-wazuh-c
-a always,exit -F arch=b32 -S execve -F auid>=1000 -F auid!=-1 -k audit-wazuh-c
EOF

sudo augenrules --load
sudo auditctl -l
```

### Step 3: Configure OpenSSH (`sshd`) for SFTP Verbose Logging & Group Access Control
**Execute on:** `vnc-server` (`11.11.2.143`)

Create the `sftp-allowed` and `sftp-denied` Linux groups, comment out the default `Subsystem sftp` line in `/etc/ssh/sshd_config`, and create `/etc/ssh/sshd_config.d/50-sftp-monitoring.conf`:

```bash
sudo groupadd -f sftp-allowed
sudo groupadd -f sftp-denied
sudo sed -i 's/^Subsystem[[:space:]]\+sftp/#Subsystem sftp/' /etc/ssh/sshd_config
```

Create `/etc/ssh/sshd_config.d/50-sftp-monitoring.conf`:
```bash
sudo tee /etc/ssh/sshd_config.d/50-sftp-monitoring.conf << 'EOF'
LogLevel VERBOSE
Subsystem sftp internal-sftp -f AUTHPRIV -l INFO

# Block SFTP and SSH shell access for users in the 'sftp-denied' group (VNC-only users)
Match Group sftp-denied
    ForceCommand /usr/bin/false
    AllowTcpForwarding no
    X11Forwarding no

# Allow SFTP-only file transfers (no interactive SSH shell) for users in 'sftp-allowed'
Match Group sftp-allowed
    ForceCommand internal-sftp -f AUTHPRIV -l INFO
    AllowTcpForwarding no
    X11Forwarding no
EOF

sudo sshd -t && sudo systemctl reload sshd
```

### Step 4: Configure 1-Second Log Streaming, `/var/log/secure`, and Real-Time Whodata FIM
**Execute on:** `vnc-server` (`11.11.2.143`)

1. Set the logcollector polling interval to 1 second in `/var/ossec/etc/local_internal_options.conf`:
   ```bash
   grep -q "logcollector.loop_timeout" /var/ossec/etc/local_internal_options.conf || echo "logcollector.loop_timeout=1" | sudo tee -a /var/ossec/etc/local_internal_options.conf
   ```

2. Update `/var/ossec/etc/ossec.conf` to enable `whodata="yes"` and `report_changes="yes"` inside `<syscheck>` and explicitly collect `/var/log/secure`:
   ```bash
   sudo cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak

   sudo sed -i 's|<directories>/etc,/usr/bin,/usr/sbin</directories>|<directories check_all="yes" whodata="yes" report_changes="yes">/etc,/usr/bin,/usr/sbin</directories>|g' /var/ossec/etc/ossec.conf
   sudo sed -i 's|<directories>/bin,/sbin,/boot</directories>|<directories check_all="yes" whodata="yes">/boot,/home,/root</directories>|g' /var/ossec/etc/ossec.conf
   sudo sed -i '/<syscheck>/,/<\/syscheck>/ s|<scan_on_start>yes</scan_on_start>|<scan_on_start>yes</scan_on_start>\n    <alert_new_files>yes</alert_new_files>|' /var/ossec/etc/ossec.conf

   grep -q "/var/log/secure" /var/ossec/etc/ossec.conf || sudo sed -i '/<location>\/var\/log\/audit\/audit.log<\/location>/!b;n;a \
   \
     <localfile>\
       <log_format>syslog</log_format>\
       <location>/var/log/secure</location>\
     </localfile>' /var/ossec/etc/ossec.conf

   sudo systemctl restart wazuh-agent
   sudo systemctl status wazuh-agent --no-pager
   ```

*(Note: The same `<syscheck>` `whodata="yes"` and `/var/log/secure` configuration was also applied to `/var/ossec/etc/ossec.conf` on `wazuh-server`.)*

---

## 6. Custom Wazuh Rules and Decoders (Completed)

### Custom PCRE2 SFTP Decoders
**Execute on:** `wazuh-server` (`11.11.2.7`)

On RHEL 9, SFTP events logged by `internal-sftp` use either the `sftp-server` or `sshd` program name. Because Wazuh's legacy `OS_Regex` parser rejects escaped brackets (`\[` and `\]`) and treats `\.+` as literal dots, we use Wazuh's `pcre2` engine (`type="pcre2"`) in `/var/ossec/etc/decoders/sftp_decoders.xml`.

Create `/var/ossec/etc/decoders/sftp_decoders.xml`:
```xml
<decoder name="sftp-server">
  <program_name>^sftp-server|^internal-sftp</program_name>
</decoder>

<decoder name="sftp-server-session">
  <parent>sftp-server</parent>
  <prematch type="pcre2">^session opened for local user </prematch>
  <regex type="pcre2">^session opened for local user (\S+) from \[(\S+)\]</regex>
  <order>dstuser, srcip</order>
</decoder>

<decoder name="sftp-server-file">
  <parent>sftp-server</parent>
  <prematch type="pcre2">^open "</prematch>
  <regex type="pcre2">^open "([^"]+)" flags (\S+) mode</regex>
  <order>file, extra_data</order>
</decoder>

<decoder name="sshd-sftp-session">
  <parent>sshd</parent>
  <prematch type="pcre2">^session opened for local user </prematch>
  <regex type="pcre2">^session opened for local user (\S+) from \[(\S+)\]</regex>
  <order>dstuser, srcip</order>
</decoder>

<decoder name="sshd-sftp-file">
  <parent>sshd</parent>
  <prematch type="pcre2">^open "</prematch>
  <regex type="pcre2">^open "([^"]+)" flags (\S+) mode</regex>
  <order>file, extra_data</order>
</decoder>
```

Command to create and set permissions on `wazuh-server`:
```bash
sudo tee /var/ossec/etc/decoders/sftp_decoders.xml << 'EOF'
<decoder name="sftp-server">
  <program_name>^sftp-server|^internal-sftp</program_name>
</decoder>

<decoder name="sftp-server-session">
  <parent>sftp-server</parent>
  <prematch type="pcre2">^session opened for local user </prematch>
  <regex type="pcre2">^session opened for local user (\S+) from \[(\S+)\]</regex>
  <order>dstuser, srcip</order>
</decoder>

<decoder name="sftp-server-file">
  <parent>sftp-server</parent>
  <prematch type="pcre2">^open "</prematch>
  <regex type="pcre2">^open "([^"]+)" flags (\S+) mode</regex>
  <order>file, extra_data</order>
</decoder>

<decoder name="sshd-sftp-session">
  <parent>sshd</parent>
  <prematch type="pcre2">^session opened for local user </prematch>
  <regex type="pcre2">^session opened for local user (\S+) from \[(\S+)\]</regex>
  <order>dstuser, srcip</order>
</decoder>

<decoder name="sshd-sftp-file">
  <parent>sshd</parent>
  <prematch type="pcre2">^open "</prematch>
  <regex type="pcre2">^open "([^"]+)" flags (\S+) mode</regex>
  <order>file, extra_data</order>
</decoder>
EOF

sudo chown wazuh:wazuh /var/ossec/etc/decoders/sftp_decoders.xml
sudo chmod 660 /var/ossec/etc/decoders/sftp_decoders.xml
```

---

## 7. Security Monitoring and Detection Rules (Completed)

### Built-In Wazuh Rules Leveraged
* **Rule `80792`:** Auditd command execution (`execve`) matched via key `audit-wazuh-c`.
* **Rules `550`, `553`, `554`:** Syscheck Real-Time Whodata File Integrity Monitoring (file modified, deleted, or added).
* **Rules `5901`, `5902`, `5903`:** Linux user/group creation, modification, or deletion.

### Custom SFTP & VNC Rules (`/var/ossec/etc/rules/sftp_and_vnc_rules.xml`)
**Execute on:** `wazuh-server` (`11.11.2.7`)

Create `/var/ossec/etc/rules/sftp_and_vnc_rules.xml`:
```xml
<group name="sftp_monitoring,">

  <rule id="100501" level="10">
    <match>session opened for local user</match>
    <description>SFTP: Session opened by user $(dstuser) from IP $(srcip)</description>
    <options>alert_by_email</options>
    <group>authentication_success,sftp_alert,</group>
  </rule>

  <rule id="100502" level="12">
    <match>flags WRITE|flags CREATE|flags TRUNCATE|flags APPEND</match>
    <description>SFTP File Upload/Write Detected: File "$(file)" opened with $(extra_data)</description>
    <options>alert_by_email</options>
    <group>syscheck,sftp_alert,</group>
  </rule>

  <rule id="100503" level="10">
    <match>flags READ</match>
    <description>SFTP File Download/Read Detected: File "$(file)" read via SFTP</description>
    <options>alert_by_email</options>
    <group>sftp_alert,</group>
  </rule>

  <rule id="100504" level="12">
    <regex>remove name "|rmdir name "|rename old "|setstat name "</regex>
    <description>SFTP File Delete/Rename/Permission change detected</description>
    <options>alert_by_email</options>
    <group>syscheck,sftp_alert,</group>
  </rule>

  <rule id="100505" level="12">
    <if_group>sshd</if_group>
    <match>Forced command '/usr/bin/false'|forced-command (config) '/usr/bin/false'|subsystem request for sftp failed</match>
    <description>SFTP Access Blocked: Unauthorized user attempted SFTP access</description>
    <options>alert_by_email</options>
    <group>authentication_failed,sftp_alert,</group>
  </rule>

  <rule id="100506" level="10">
    <if_sid>80700</if_sid>
    <field name="audit.key">vnc-config-modify</field>
    <description>VNC Configuration Modified by user $(audit.auid)</description>
    <options>alert_by_email</options>
    <group>vnc_monitoring,</group>
  </rule>

</group>
```

Command to create and set permissions on `wazuh-server`:
```bash
sudo tee /var/ossec/etc/rules/sftp_and_vnc_rules.xml << 'EOF'
<group name="sftp_monitoring,">

  <rule id="100501" level="10">
    <match>session opened for local user</match>
    <description>SFTP: Session opened by user $(dstuser) from IP $(srcip)</description>
    <options>alert_by_email</options>
    <group>authentication_success,sftp_alert,</group>
  </rule>

  <rule id="100502" level="12">
    <match>flags WRITE|flags CREATE|flags TRUNCATE|flags APPEND</match>
    <description>SFTP File Upload/Write Detected: File "$(file)" opened with $(extra_data)</description>
    <options>alert_by_email</options>
    <group>syscheck,sftp_alert,</group>
  </rule>

  <rule id="100503" level="10">
    <match>flags READ</match>
    <description>SFTP File Download/Read Detected: File "$(file)" read via SFTP</description>
    <options>alert_by_email</options>
    <group>sftp_alert,</group>
  </rule>

  <rule id="100504" level="12">
    <regex>remove name "|rmdir name "|rename old "|setstat name "</regex>
    <description>SFTP File Delete/Rename/Permission change detected</description>
    <options>alert_by_email</options>
    <group>syscheck,sftp_alert,</group>
  </rule>

  <rule id="100505" level="12">
    <if_group>sshd</if_group>
    <match>Forced command '/usr/bin/false'|forced-command (config) '/usr/bin/false'|subsystem request for sftp failed</match>
    <description>SFTP Access Blocked: Unauthorized user attempted SFTP access</description>
    <options>alert_by_email</options>
    <group>authentication_failed,sftp_alert,</group>
  </rule>

  <rule id="100506" level="10">
    <if_sid>80700</if_sid>
    <field name="audit.key">vnc-config-modify</field>
    <description>VNC Configuration Modified by user $(audit.auid)</description>
    <options>alert_by_email</options>
    <group>vnc_monitoring,</group>
  </rule>

</group>
EOF

sudo chown wazuh:wazuh /var/ossec/etc/rules/sftp_and_vnc_rules.xml
sudo chmod 660 /var/ossec/etc/rules/sftp_and_vnc_rules.xml
```

**Validation:**
```bash
sudo /var/ossec/bin/wazuh-analysisd -t
```

---

## 8. Email Notification Configuration (Completed)

### Step 1: Install Postfix & Cyrus SASL Packages
**Execute on:** `wazuh-server` (`11.11.2.7`)

```bash
sudo dnf install -y postfix cyrus-sasl cyrus-sasl-plain s-nail
sudo systemctl enable --now postfix
```

### Step 2: Configure Postfix Gmail SMTP Relay with App Password
**Execute on:** `wazuh-server` (`11.11.2.7`)

1. Create `/etc/postfix/sasl_passwd` with your Gmail address and 16-character Google App Password:
   ```bash
   sudo tee /etc/postfix/sasl_passwd << 'EOF'
   [smtp.gmail.com]:587 <SENDER_EMAIL_ADDRESS>:<GMAIL_16_CHAR_APP_PASSWORD>
   EOF

   sudo chmod 600 /etc/postfix/sasl_passwd
   sudo postmap /etc/postfix/sasl_passwd
   ```

2. Comment out the default `smtp_tls_security_level = may` entry in `/etc/postfix/main.cf` (to prevent duplicate parameter warnings) and append the Gmail relay settings:
   ```bash
   sudo sed -i 's/^smtp_tls_security_level = may/#smtp_tls_security_level = may/' /etc/postfix/main.cf

   sudo tee -a /etc/postfix/main.cf << 'EOF'

   # Gmail SMTP Relay Configuration
   relayhost = [smtp.gmail.com]:587
   smtp_use_tls = yes
   smtp_sasl_auth_enable = yes
   smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd
   smtp_sasl_security_options = noanonymous
   smtp_tls_security_level = encrypt
   smtp_tls_cafile = /etc/ssl/certs/ca-bundle.crt
   EOF

   sudo systemctl restart postfix
   ```

**Validation (Test Postfix Relay Directly):**
```bash
echo "Test email body from Wazuh Server" | mail -s "Postfix Relay Test" <RECIPIENT_EMAIL_ADDRESS>
sudo tail -n 15 /var/log/maillog
```

### Step 3: Enable Email Notification in Wazuh (`/var/ossec/etc/ossec.conf`)
**Execute on:** `wazuh-server` (`11.11.2.7`)

Configure `<global>` and `<email_alerts>` in `/var/ossec/etc/ossec.conf`:

```xml
<global>
  <jsonout_output>yes</jsonout_output>
  <alerts_log>yes</alerts_log>
  <logall>no</logall>
  <logall_json>no</logall_json>
  <email_notification>yes</email_notification>
  <smtp_server>localhost</smtp_server>
  <email_from><SENDER_EMAIL_ADDRESS></email_from>
  <email_to><RECIPIENT_EMAIL_ADDRESS></email_to>
  <email_maxperhour>1000</email_maxperhour>
  <email_log_source>alerts.log</email_log_source>
</global>
```

Command used to update `/var/ossec/etc/ossec.conf` on `wazuh-server`:
```bash
sudo sed -i 's|<email_notification>no</email_notification>|<email_notification>yes</email_notification>|' /var/ossec/etc/ossec.conf
sudo sed -i 's|<smtp_server>smtp.example.wazuh.com</smtp_server>|<smtp_server>localhost</smtp_server>|' /var/ossec/etc/ossec.conf
sudo sed -i 's|<email_from>wazuh@example.wazuh.com</email_from>|<email_from><SENDER_EMAIL_ADDRESS></email_from>|' /var/ossec/etc/ossec.conf
sudo sed -i 's|<email_to>recipient@example.wazuh.com</email_to>|<email_to><RECIPIENT_EMAIL_ADDRESS></email_to>|' /var/ossec/etc/ossec.conf
sudo sed -i 's|<email_maxperhour>12</email_maxperhour>|<email_maxperhour>1000</email_maxperhour>|' /var/ossec/etc/ossec.conf
```

---

## 9. Brute-Force Attack Detection and Email Alerts (Additional Configuration To Perform)

### How Threshold Detection & Email Suppression Work
In our initial setup, we added an `<email_alerts>` block containing individual failed login rules (`5710, 5712, 5716, 5760`), which sends an email on **every single failed password typo**.

To alert and email **only when a user or source IP fails authentication 5 times within 10 minutes (600 seconds)**—while still emailing immediately on all SFTP events (`100501`–`100505`)—perform the following two steps on `wazuh-server`.

* **How Wazuh Counts `frequency="5"`:** In Wazuh's rule engine, `frequency="5"` triggers when the current event matches alongside multiple prior matching events within `timeframe="600"` (10 minutes).
* **Matching Conditions:** We match on `<if_matched_group>authentication_failed</if_matched_group>` (which covers SSH/SFTP invalid users `5710`, failed passwords `5716`, and PAM authentication failures `5503`) correlated by either `<same_source_ip />` (Rule `100510`) or `<same_user />` (Rule `100511`).

### Step 1: Add the 5-in-10-Minute Brute-Force Rules (`100510` and `100511`)
**Execute on:** `wazuh-server` (`11.11.2.7`)

Update `/var/ossec/etc/rules/sftp_and_vnc_rules.xml` to include Rules `100510` and `100511`:

```xml
<group name="sftp_monitoring,brute_force_detection,">

  <!-- 1. SFTP Session Opened -->
  <rule id="100501" level="10">
    <match>session opened for local user</match>
    <description>SFTP: Session opened by user $(dstuser) from IP $(srcip)</description>
    <options>alert_by_email</options>
    <group>authentication_success,sftp_alert,</group>
  </rule>

  <!-- 2. SFTP File Uploaded / Written -->
  <rule id="100502" level="12">
    <match>flags WRITE|flags CREATE|flags TRUNCATE|flags APPEND</match>
    <description>SFTP File Upload/Write Detected: File "$(file)" opened with $(extra_data)</description>
    <options>alert_by_email</options>
    <group>syscheck,sftp_alert,</group>
  </rule>

  <!-- 3. SFTP File Downloaded / Read -->
  <rule id="100503" level="10">
    <match>flags READ</match>
    <description>SFTP File Download/Read Detected: File "$(file)" read via SFTP</description>
    <options>alert_by_email</options>
    <group>sftp_alert,</group>
  </rule>

  <!-- 4. SFTP File Deleted, Renamed, or Permission Changed -->
  <rule id="100504" level="12">
    <regex>remove name "|rmdir name "|rename old "|setstat name "</regex>
    <description>SFTP File Delete/Rename/Permission change detected</description>
    <options>alert_by_email</options>
    <group>syscheck,sftp_alert,</group>
  </rule>

  <!-- 5. Blocked SFTP User (sftp-denied group triggered ForceCommand /usr/bin/false) -->
  <rule id="100505" level="12">
    <if_group>sshd</if_group>
    <match>Forced command '/usr/bin/false'|forced-command (config) '/usr/bin/false'|subsystem request for sftp failed</match>
    <description>SFTP Access Blocked: Unauthorized user attempted SFTP access</description>
    <options>alert_by_email</options>
    <group>authentication_failed,sftp_alert,</group>
  </rule>

  <!-- 6. TigerVNC Configuration Modified -->
  <rule id="100506" level="10">
    <if_sid>80700</if_sid>
    <field name="audit.key">vnc-config-modify</field>
    <description>VNC Configuration Modified by user $(audit.auid)</description>
    <options>alert_by_email</options>
    <group>vnc_monitoring,</group>
  </rule>

  <!-- 7. Brute-Force Attack by Source IP: 5 Failed Logins within 10 Minutes (600s) -->
  <rule id="100510" level="12" frequency="5" timeframe="600">
    <if_matched_group>authentication_failed</if_matched_group>
    <same_source_ip />
    <description>Brute-Force Attack Detected: 5 failed login attempts within 10 minutes from IP $(srcip) (last target user: $(dstuser))</description>
    <mitre>
      <id>T1110</id>
    </mitre>
    <options>alert_by_email</options>
    <group>authentication_failures,brute_force_alert,</group>
  </rule>

  <!-- 8. Brute-Force Attack by Target Username: 5 Failed Logins within 10 Minutes (600s) -->
  <rule id="100511" level="12" frequency="5" timeframe="600">
    <if_matched_group>authentication_failed</if_matched_group>
    <same_user />
    <description>Brute-Force Attack Detected: 5 failed login attempts within 10 minutes for user $(dstuser) (from IP $(srcip))</description>
    <mitre>
      <id>T1110</id>
    </mitre>
    <options>alert_by_email</options>
    <group>authentication_failures,brute_force_alert,</group>
  </rule>

</group>
```

Command to apply the updated rule file on `wazuh-server`:
```bash
sudo tee /var/ossec/etc/rules/sftp_and_vnc_rules.xml << 'EOF'
<group name="sftp_monitoring,brute_force_detection,">

  <rule id="100501" level="10">
    <match>session opened for local user</match>
    <description>SFTP: Session opened by user $(dstuser) from IP $(srcip)</description>
    <options>alert_by_email</options>
    <group>authentication_success,sftp_alert,</group>
  </rule>

  <rule id="100502" level="12">
    <match>flags WRITE|flags CREATE|flags TRUNCATE|flags APPEND</match>
    <description>SFTP File Upload/Write Detected: File "$(file)" opened with $(extra_data)</description>
    <options>alert_by_email</options>
    <group>syscheck,sftp_alert,</group>
  </rule>

  <rule id="100503" level="10">
    <match>flags READ</match>
    <description>SFTP File Download/Read Detected: File "$(file)" read via SFTP</description>
    <options>alert_by_email</options>
    <group>sftp_alert,</group>
  </rule>

  <rule id="100504" level="12">
    <regex>remove name "|rmdir name "|rename old "|setstat name "</regex>
    <description>SFTP File Delete/Rename/Permission change detected</description>
    <options>alert_by_email</options>
    <group>syscheck,sftp_alert,</group>
  </rule>

  <rule id="100505" level="12">
    <if_group>sshd</if_group>
    <match>Forced command '/usr/bin/false'|forced-command (config) '/usr/bin/false'|subsystem request for sftp failed</match>
    <description>SFTP Access Blocked: Unauthorized user attempted SFTP access</description>
    <options>alert_by_email</options>
    <group>authentication_failed,sftp_alert,</group>
  </rule>

  <rule id="100506" level="10">
    <if_sid>80700</if_sid>
    <field name="audit.key">vnc-config-modify</field>
    <description>VNC Configuration Modified by user $(audit.auid)</description>
    <options>alert_by_email</options>
    <group>vnc_monitoring,</group>
  </rule>

  <rule id="100510" level="12" frequency="5" timeframe="600">
    <if_matched_group>authentication_failed</if_matched_group>
    <same_source_ip />
    <description>Brute-Force Attack Detected: 5 failed login attempts within 10 minutes from IP $(srcip) (last target user: $(dstuser))</description>
    <mitre>
      <id>T1110</id>
    </mitre>
    <options>alert_by_email</options>
    <group>authentication_failures,brute_force_alert,</group>
  </rule>

  <rule id="100511" level="12" frequency="5" timeframe="600">
    <if_matched_group>authentication_failed</if_matched_group>
    <same_user />
    <description>Brute-Force Attack Detected: 5 failed login attempts within 10 minutes for user $(dstuser) (from IP $(srcip))</description>
    <mitre>
      <id>T1110</id>
    </mitre>
    <options>alert_by_email</options>
    <group>authentication_failures,brute_force_alert,</group>
  </rule>

</group>
EOF

sudo chown wazuh:wazuh /var/ossec/etc/rules/sftp_and_vnc_rules.xml
sudo chmod 660 /var/ossec/etc/rules/sftp_and_vnc_rules.xml
```

### Step 2: Update `<email_alerts>` in `/var/ossec/etc/ossec.conf` to Suppress Single-Failure Email Noise
**Execute on:** `wazuh-server` (`11.11.2.7`)

Replace the `<rule_id>5710, 5712, 5716, 5720, 5760...</rule_id>` line in `/var/ossec/etc/ossec.conf` so individual failed logins (`5710`, `5716`) are still logged to the Wazuh Dashboard (Level 5), **but emails are only sent when the 5-attempt threshold (`100510`, `100511`) or SFTP rules (`100501`–`100505`) fire**:

```bash
sudo sed -i 's|<rule_id>5710, 5712, 5716, 5720, 5760, 100501, 100502, 100503, 100504, 100505</rule_id>|<rule_id>100501, 100502, 100503, 100504, 100505, 100510, 100511</rule_id>|' /var/ossec/etc/ossec.conf

sudo /var/ossec/bin/wazuh-analysisd -t && sudo systemctl restart wazuh-manager
```

### Step 3: Test Brute-Force Detection and Email Delivery
1. **Dry-Run Verification with `wazuh-logtest` on `wazuh-server`:**
   Feed 5 consecutive failed SSH/SFTP login attempts from the same IP within a single session:
   ```bash
   sudo /var/ossec/bin/wazuh-logtest << 'EOF'
   Nov  5 18:00:01 vnc-server sshd[31001]: Failed password for eng-001 from 11.11.2.99 port 51001 ssh2
   Nov  5 18:00:05 vnc-server sshd[31002]: Failed password for eng-001 from 11.11.2.99 port 51002 ssh2
   Nov  5 18:00:10 vnc-server sshd[31003]: Failed password for eng-001 from 11.11.2.99 port 51003 ssh2
   Nov  5 18:00:15 vnc-server sshd[31004]: Failed password for eng-001 from 11.11.2.99 port 51004 ssh2
   Nov  5 18:00:20 vnc-server sshd[31005]: Failed password for eng-001 from 11.11.2.99 port 51005 ssh2
   EOF
   ```
   *Expected Result:* Attempts 1–4 trigger Rule `5716` (`level: '5'`, no email), while the 5th attempt triggers **Rule `100510` (`level: '12'`, `mail: 'True'`)**.

2. **Live End-to-End Email Test from `vnc-server` (`11.11.2.143`):**
   Run this loop on `vnc-server` to inject 5 failed login events into `/var/log/secure`:
   ```bash
   for i in {1..5}; do
     sudo logger -p authpriv.info -t "sshd[3200$i]" "Failed password for eng-001 from 11.11.2.99 port 5200$i ssh2"
     sleep 1
   done
   ```

3. **Verify the Alert and Email Delivery on `wazuh-server` (`11.11.2.7`):**
   *(Note: Wazuh stores alert logs in `/var/ossec/logs/alerts/alerts.log`, not `/var/log/alerts/alerts.log`.)*
   ```bash
   sudo tail -n 30 /var/ossec/logs/alerts/alerts.log
   sudo tail -n 20 /var/log/maillog
   ```

---

## 10. Testing, Troubleshooting, and Validation

### Summary of Errors Encountered & How They Were Resolved

| Error / Symptom Encountered | Root Cause | Resolution Applied |
| :--- | :--- | :--- |
| `ERROR: Wazuh dashboard installation failed` (Automatic Rollback) | Small root disk (`29 GB`), `0` swap memory, and missing `fontconfig`/`lsof` packages during unpacking of the 286 MB `wazuh-dashboard` RPM. | Provisioned 100 GB root disk, added 4 GB `/swapfile`, increased DNF timeout (`timeout=300`), and pre-installed `fontconfig`, `lsof`, `libcap`, and `nss`. |
| `Failed to restart auditd.service: Operation refused` | RHEL 9 configures `auditd.service` with `RefuseManualStop=yes` to prevent tampering via `systemctl`. | Used `sudo augenrules --load` (which reloads kernel rules dynamically) or `sudo service auditd restart` instead of `systemctl`. |
| `wazuh-manager.service failed` after running `sed` for `<alert_new_files>` | Running `grep -q` without `sudo` returned `Permission denied`, triggering `\|\| sudo sed` across all `<scan_on_start>` tags in `<syscollector>` and `<sca>`. | Restored `/var/ossec/etc/ossec.conf.bak` and scoped the `sed` command strictly to `/<syscheck>/,/<\/syscheck>/`. |
| `Error sending add rule data request (Rule exists)` in `auditd` | Both `wazuh-command-audit.rules` and `wazuh-full-monitoring.rules` existed in `/etc/audit/rules.d/`, and `/etc/tigervnc/` did not exist yet. | Removed the duplicate `wazuh-command-audit.rules` file, ran `sudo mkdir -p /etc/tigervnc`, and ran `sudo augenrules --load`. |
| `XMLERR: Element 'email_maxperhour' not closed. (line 17)` | Copy-paste typo in `sed` command created `<email_maxperhour>1000</email_maxgmail.comperhour>`. | Fixed closing tag to `<email_maxperhour>1000</email_maxperhour>` and verified with `sudo /var/ossec/bin/wazuh-analysisd -t`. |
| `Unit wazuh-agent.service not found` | Agent setup commands were accidentally pasted into the `wazuh-server` terminal (`[root@wazuh-server]#`). | Removed `/etc/ssh/sshd_config.d/50-sftp-monitoring.conf` from `wazuh-server`, restored `wazuh-server` config, and ran agent commands on `vnc-server` (`11.11.2.143`). |
| `ERROR: (1452): Syntax error on regex: '^session opened for local user (\S+) from \[(\S+)\]'` | Wazuh's default `OS_Regex` parser does not support `\[` and `\]` or `[^"]+` character classes. | Added `type="pcre2"` to `<prematch type="pcre2">` and `<regex type="pcre2">` in `/var/ossec/etc/decoders/sftp_decoders.xml`. |
| `tail: cannot open '/var/log/alerts/alerts.log': No such file or directory` | Wazuh stores alerts inside `/var/ossec/logs/alerts/alerts.log` (not `/var/log/`). | Use `sudo tail -f /var/ossec/logs/alerts/alerts.log`. |

### Essential Validation & Troubleshooting Commands

**Execute on `wazuh-server` (`11.11.2.7`):**
```bash
# 1. Validate XML syntax of ossec.conf, custom decoders, and custom rules
sudo /var/ossec/bin/wazuh-analysisd -t

# 2. Check status of all Wazuh Server services
sudo systemctl status wazuh-indexer wazuh-manager filebeat wazuh-dashboard --no-pager

# 3. Verify connected agents
sudo /var/ossec/bin/agent_control -l

# 4. Watch live Wazuh alerts (correct file path)
sudo tail -f /var/ossec/logs/alerts/alerts.log

# 5. Watch live Postfix email relay delivery logs
sudo tail -f /var/log/maillog
```

**Execute on `vnc-server` (`11.11.2.143`):**
```bash
# 1. Verify Wazuh Agent service and manager connection
sudo systemctl status wazuh-agent --no-pager
sudo grep -E "Connected to the server|Whodata" /var/ossec/logs/ossec.log

# 2. Verify active kernel auditd rules
sudo auditctl -l

# 3. Trigger a live SFTP file upload alert & email end-to-end
sudo logger -p authpriv.info -t sftp-server 'open "/home/ec2-user/test_chip_layout.gds" flags WRITE,CREATE,TRUNCATE mode 0664'
```
