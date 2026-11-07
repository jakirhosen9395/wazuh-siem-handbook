# Wazuh v4.14.9 Complete Installation, SSH/SFTP User Monitoring & Configurable HTML Email Alert Runbook

This master runbook covers both the **complete Wazuh v4.14.9 installation from scratch** on Red Hat Enterprise Linux (RHEL) 9.8 and the **audited production fix and upgrade** for universal Linux/VNC user monitoring, granular SFTP transfer tracking, multi-tier SSH brute-force detection (5-attempt Medium and 10-attempt High), and a centralized, category-based HTML email notification system.

---

## 1. Root-Cause Audit of Existing Issues & Architectural Fixes

An audit of the existing configuration (`/var/ossec/etc/ossec.conf`, `/var/ossec/etc/decoders/sftp_decoders.xml`, `/var/ossec/etc/rules/`, `/etc/ssh/sshd_config`, `/etc/ssh/sshd_config.d/50-sftp-monitoring.conf`, and `/var/ossec/integrations/custom-html-email.py`) identified five specific root causes behind the issues you experienced:

### 1.1 Why `ec2-user` Generated SFTP Notifications While Newly Created Linux/VNC Users Did Not
1. **OpenSSH `Include` Ordering & `Match Group` Scoping in `/etc/ssh/sshd_config`:**
   * On RHEL 9, `/etc/ssh/sshd_config` places `Include /etc/ssh/sshd_config.d/*.conf` at the **top** of the file and defines `Subsystem sftp /usr/libexec/openssh/sftp-server` at the bottom. Additionally, any directive placed after a `Match Group` block inside a drop-in file only applies to that group.
   * When you created a new Linux user (`sudo useradd newuser1`) without adding them to `sftp-allowed`, or if `/etc/ssh/sshd_config` still had an active `Subsystem sftp` line, OpenSSH fell back to the default `/usr/libexec/openssh/sftp-server` binary **without** `-f AUTHPRIV -l INFO`, producing **zero** SFTP file transfer logs in `/var/log/secure`.
   * **Fix:** Set `Subsystem sftp internal-sftp -f AUTHPRIV -l INFO` globally in `/etc/ssh/sshd_config.d/50-sftp-monitoring.conf` *above* all `Match` blocks and comment out any other `Subsystem sftp` lines in `/etc/ssh/sshd_config` and `/etc/ssh/sshd_config.d/`. Every newly created Linux user (`useradd newuser1`) is now automatically logged by `internal-sftp -l INFO` without needing manual group assignment just to get logs.
2. **OpenSSH `internal-sftp` Multi-Line PID Context Split:**
   * OpenSSH logs SFTP sessions across separate syslog lines sharing the same `sshd[PID]`:
     * Session start: `sshd[24110]: session opened for local user newuser1 from [11.11.2.50]` (contains `dstuser` and `srcip`, **no** filename).
     * File open (upload/download attempt): `sshd[24110]: open "/home/newuser1/chip.gds" flags WRITE,CREATE,TRUNCATE mode 0664` (contains `file` and `flags`, **no** `dstuser` or `srcip` field on the line).
     * File close (transfer completed): `sshd[24110]: close "/home/newuser1/chip.gds" bytes read 0 written 40960` (contains `file` and bytes transferred, **no** `dstuser` or `srcip` field on the line).
     * Operation denied: `sshd[24110]: sent status Permission denied` (contains **no** username, IP, or filename on the raw line).
   * Previously, the decoders only matched `open "..."` and did not extract the username from `/home/<username>/...` or correlate the `sshd[PID]` session cache.
   * **Fix:** Updated `/var/ossec/etc/decoders/sftp_decoders.xml` and `/var/ossec/integrations/custom-html-email.py` to cache `(agent_id, pid) -> {username, srcip, last_file}` whenever an SSH/SFTP session opens (`Rule 5715` / `100501`) and also extract `/home/<username>/` paths directly. Every SFTP upload attempt, download, completion (`close`), and `Permission denied` failure now resolves the exact username, source IP, and file path for **all** users automatically.
3. **Blocked SFTP Users (`sftp-denied` Group) Log Format Mismatch:**
   * When a user in `sftp-denied` attempts an SFTP connection, `sshd` logs `Accepted password for <user> from <ip>...` followed by `Starting session: forced-command (config) '/usr/bin/false' for <user> from <ip> port <port> id 0`.
   * Previously, `sshd` did not decode `dstuser` and `srcip` on the `forced-command` line. We added a dedicated PCRE2 child decoder (`sshd-sftp-blocked`) so `Rule 100505` captures both the username and source IP.
4. **VNC Authentication Uses PAM / TigerVNC (`Xvnc`), Not `sshd`:**
   * Connecting to TigerVNC (`:1`, `:2`, etc.) authenticates via `/etc/pam.d/tigervnc` and logs to `/var/log/secure` (`pam_unix(tigervnc:session)`) and `/home/*/.vnc/*.log`.
   * **Fix:** Added `/home/*/.vnc/*.log` collection on the agent and created dedicated VNC authentication/session rules (`100509` and `100510`).

### 1.2 Why Too Many Emails Were Sent & How 5-Attempt vs. 10-Attempt Brute-Force Works
1. **Excessive Emails:** Previously, `email_notify_alert` was attached to general SSH rules, port changes, and SFTP session opens (`100501`), causing emails even when a user merely connected via SFTP without transferring a file.
2. **5-Attempt (`[MEDIUM]`) vs. 10-Attempt (`[HIGH]`) Correlation:**
   * In Wazuh's `analysisd` engine, a `frequency="5"` rule (`100601`) will fire on attempt #5, and—if not suppressed—will fire again on attempts #6, #7, #8, and #9 because there are still $\ge 5$ failures within the 5-minute window. Furthermore, if Rule `100601` does not retain the `authentication_failed` group or if it is evaluated before the 10-attempt rule, it can prevent the 10-attempt rule from counting event #5.
   * **Fix:**
     * Both the 5-attempt (`100601`, `100602`) and 10-attempt (`100611`, `100612`) rules include `authentication_failed` in their `<group>` tags so every failed attempt continues incrementing the correlation counter.
     * The **10-attempt High-Severity rules (`100611`, `100612`, Level 12)** are placed **above** the **5-attempt Medium-Severity rules (`100601`, `100602`, Level 8)** in `/var/ossec/etc/rules/ssh_and_network_rules.xml`, so on attempt #10 Wazuh matches the High-Severity rule first.
     * The Python integration script maintains a 5-minute deduplication tracker per `(agent_id, rule_id, srcip, dstuser)` so that attempt #5 sends **one** `[MEDIUM] SSH Brute-Force Activity Detected` email, attempts #6–#9 do **not** send duplicate Medium emails, and attempt #10 sends **one** `[HIGH] SSH Brute-Force Attack Detected` email.

---

## 2. Summary of Files Modified, Backup Locations & Email Notification Policy

### 2.1 Files Modified & Backup Locations

| Server | File Path | Action | Backup Location |
| :--- | :--- | :--- | :--- |
| **Wazuh Agent** (`vnc-server`) | `/etc/ssh/sshd_config` | Modified (Commented out legacy `Subsystem sftp`) | `/etc/ssh/sshd_config.bak` |
| **Wazuh Agent** (`vnc-server`) | `/etc/ssh/sshd_config.d/50-sftp-monitoring.conf` | Updated global `internal-sftp -l INFO` & `Match` blocks | `/etc/ssh/sshd_config.d/50-sftp-monitoring.conf.bak` |
| **Wazuh Agent** (`vnc-server`) | `/etc/audit/rules.d/wazuh-full-monitoring.rules` | Updated kernel `auditd` rules for all users (`auid>=1000`) | `/etc/audit/rules.d/wazuh-full-monitoring.rules.bak` |
| **Wazuh Agent** (`vnc-server`) | `/var/ossec/etc/ossec.conf` | Added `/home/*/.vnc/*.log` & verified `/var/log/secure` | `/var/ossec/etc/ossec.conf.bak` |
| **Wazuh Manager** (`wazuh-server`) | `/var/ossec/etc/ossec.conf` | Configured centralized `<integration>` hook | `/var/ossec/etc/ossec.conf.bak` |
| **Wazuh Manager** (`wazuh-server`) | `/var/ossec/etc/decoders/sftp_decoders.xml` | Added PCRE2 decoders for `open`, `close`, `denied`, `vnc` | `/var/ossec/etc/decoders/sftp_decoders.xml.bak` |
| **Wazuh Manager** (`wazuh-server`) | `/var/ossec/etc/rules/sftp_and_vnc_rules.xml` | Updated SFTP attempt, completion, denied & VNC rules | `/var/ossec/etc/rules/sftp_and_vnc_rules.xml.bak` |
| **Wazuh Manager** (`wazuh-server`) | `/var/ossec/etc/rules/ssh_and_network_rules.xml` | Added 5-attempt (Medium) & 10-attempt (High) SSH rules | `/var/ossec/etc/rules/ssh_and_network_rules.xml.bak` |
| **Wazuh Manager** (`wazuh-server`) | `/var/ossec/etc/email_notification_policy.json` | Created centralized category email policy toggle file | `/var/ossec/etc/email_notification_policy.json.bak` |
| **Wazuh Manager** (`wazuh-server`) | `/var/ossec/integrations/custom-html-email.py` | Upgraded to 6-section HTML template + PID session cache | `/var/ossec/integrations/custom-html-email.py.bak` |

### 2.2 Centralized Email Notification Policy Matrix

All events continue to be collected, decoded, and displayed in the **Wazuh Dashboard** and `/var/ossec/logs/alerts/alerts.json`. Email delivery is controlled centrally by `/var/ossec/etc/email_notification_policy.json`:

| Policy Category Key | Event Category Description | Associated Rule IDs / Groups | Default Email Status |
| :--- | :--- | :--- | :--- |
| `sftp_successful_transfers` | SFTP file upload/download attempt, transfer completed, delete/rename | `100502`, `100503`, `100504`, `100507` (`notify_sftp_transfer`) | **Enabled (`true`)** |
| `sftp_failed_denied_operations` | SFTP access denied (`sftp-denied` group) or file permission/transfer failure | `100505`, `100508` (`notify_sftp_denied`) | **Enabled (`true`)** |
| `ssh_bruteforce_detection` | SSH brute-force: 5 failures in 5m (**Medium**) & 10 failures in 5m (**High**) | `100601`, `100602` (Medium), `100611`, `100612` (High) (`notify_ssh_bruteforce`) | **Enabled (`true`)** |
| `sftp_connection_attempts` | SFTP session opened / closed (without file transfer) | `100501`, `100511` (`notify_sftp_connect`) | **Disabled (`false`)** *(Configurable)* |
| `ssh_authentication_events` | Individual SSH successful login (`5715`) or single failed password (`5716`) | `5715`, `5716`, `5710` (`notify_ssh_auth`) | **Disabled (`false`)** *(Configurable)* |
| `ssh_suspicious_login` | Multi-IP login (`100603`), username spraying (`100604`), login after brute-force (`100605`), root login (`100606`), external IP (`100608`), off-hours (`100609`) | `100603`–`100610` (`notify_ssh_suspicious`) | **Disabled (`false`)** *(Configurable)* |
| `linux_user_creation_deletion` | New Linux user created (`useradd`), modified (`usermod`), or deleted (`userdel`) | `5902`, `5903`, `5904`, `100630` (`notify_user_mgmt`) | **Disabled (`false`)** *(Configurable)* |
| `linux_group_changes` | Linux group created or membership modified (`gpasswd`, `usermod -aG`, `/etc/group`) | `5901`, `100631` (`notify_group_mgmt`) | **Disabled (`false`)** *(Configurable)* |
| `vnc_session_events` | TigerVNC authentication success, failure, or config change | `100506`, `100509`, `100510` (`notify_vnc`) | **Disabled (`false`)** *(Configurable)* |
| `file_integrity_monitoring` | Real-time Whodata FIM file changes (`550`, `553`, `554`) | `syscheck` (`notify_fim`) | **Disabled (`false`)** *(Configurable)* |
| `other_security_alerts` | Port changes (`100620`), firewall drops (`100623`), and other Wazuh alerts | `notify_other` | **Disabled (`false`)** *(Configurable)* |

---

## 3. Complete Wazuh Server & Agent Installation from Scratch (Reference Baseline)

*(If your Wazuh v4.14.9 Server and Agent are already installed and running, skip directly to **Section 4** to apply the audited fixes and upgrades.)*

### Step 1: Prepare RHEL 9.8 Server Prerequisites (Swap, Kernel Parameters, 100 GB Disk, Dependencies)
* **Server:** Wazuh Manager (`wazuh-server` — `172.31.12.109`, RHEL 9.8)

```bash
# 1. Update OS packages and reboot if kernel was updated
sudo dnf clean all && sudo dnf makecache
sudo dnf upgrade -y
sudo dnf needs-restarting -r || sudo reboot

# 2. Set hostname, create 4 GB Swap file, and configure OpenSearch kernel parameters
sudo hostnamectl set-hostname wazuh-server
sudo fallocate -l 4G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
grep -q '/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab

cat << 'EOF' | sudo tee /etc/sysctl.d/99-wazuh.conf
vm.max_map_count=262144
vm.swappiness=10
EOF
sudo sysctl --system

# 3. Expand root partition if needed and install required dependencies
sudo dnf install -y cloud-utils-growpart curl tar coreutils gnupg2 lsof libcap fontconfig nss openssl-libs policycoreutils-python-utils
sudo growpart /dev/nvme0n1 4 || true
sudo xfs_growfs /

# 4. Increase DNF timeout and open firewalld ports
grep -q '^timeout=' /etc/dnf/dnf.conf || echo -e "timeout=300\nretries=10\nminrate=1000" | sudo tee -a /etc/dnf/dnf.conf
if systemctl is-active --quiet firewalld; then
    sudo firewall-cmd --permanent --add-port={443/tcp,1514/tcp,1515/tcp,55000/tcp}
    sudo firewall-cmd --reload
fi
```

### Step 2: Install Wazuh v4.14.9 All-in-One Stack (Indexer, Manager, Filebeat, Dashboard)
* **Server:** Wazuh Manager (`wazuh-server` — `172.31.12.109`, RHEL 9.8)

```bash
cd ~
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
sudo bash ./wazuh-install.sh -a -i -v

# Back up installation certificates/passwords and disable auto-updates on wazuh.repo
sudo cp ~/wazuh-install-files.tar /root/wazuh-install-files-backup.tar
sudo chmod 600 /root/wazuh-install-files-backup.tar
sudo sed -i "s/^enabled=1/enabled=0/" /etc/yum.repos.d/wazuh.repo
sudo systemctl status wazuh-indexer wazuh-manager filebeat wazuh-dashboard --no-pager
```

### Step 3: Install and Register Wazuh Agent v4.14.9 on Monitored Linux Server
* **Server:** Wazuh Agent (`vnc-server` — `172.31.15.219`, RHEL 9.8)

```bash
sudo dnf install -y audit curl coreutils
sudo systemctl enable --now auditd

sudo rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
curl -o wazuh-agent-4.14.9-1.x86_64.rpm https://packages.wazuh.com/4.x/yum/wazuh-agent-4.14.9-1.x86_64.rpm && \
sudo WAZUH_MANAGER='172.31.12.109' WAZUH_AGENT_NAME='vnc-server' rpm -ihv wazuh-agent-4.14.9-1.x86_64.rpm
rm -f wazuh-agent-4.14.9-1.x86_64.rpm

grep -q "logcollector.loop_timeout" /var/ossec/etc/local_internal_options.conf || \
echo "logcollector.loop_timeout=1" | sudo tee -a /var/ossec/etc/local_internal_options.conf

sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-agent
```

---

## 4. Phase 1 of Fix: Universal SSH, SFTP & VNC Monitoring on the Wazuh Agent (`vnc-server`)

Execute Steps 4, 5, and 6 on the **Monitored Linux Agent (`vnc-server` — `172.31.15.219`)** so that `ec2-user`, all existing users, and any newly created Linux or VNC users (`useradd newuser1`) are automatically monitored for SSH, SFTP, and VNC activity.

### Step 4: Back Up Agent Configurations and Fix Global OpenSSH / SFTP Logging
* **Server:** Wazuh Agent (`vnc-server` — `172.31.15.219`, RHEL 9.8)
* **Files Modified:** `/etc/ssh/sshd_config`, `/etc/ssh/sshd_config.d/50-sftp-monitoring.conf`

#### Why This Fix Is Critical:
By placing `LogLevel VERBOSE` and `Subsystem sftp internal-sftp -f AUTHPRIV -l INFO` at the top of `/etc/ssh/sshd_config.d/50-sftp-monitoring.conf` (before any `Match Group` blocks) and commenting out any other `Subsystem sftp` lines in `/etc/ssh/sshd_config*`, **every Linux user created now or in the future** automatically logs verbose SSH and SFTP file events (`open`, `close`, `remove`, `rename`, `Permission denied`) to `/var/log/secure`.
* Users added to `sftp-denied` (`sudo usermod -aG sftp-denied <username>`) are blocked from SFTP and trigger `Rule 100505` (`[HIGH] SFTP Access Denied`).
* Users added to `sftp-allowed` (`sudo usermod -aG sftp-allowed <username>`) are restricted to SFTP-only file transfers (no interactive SSH shell) with full `-l INFO` file logging.
* Standard Linux users (like `ec2-user` or a new `useradd newuser1` not in `sftp-denied`) have normal SSH and SFTP access with full `-l INFO` file logging.

#### Configuration (`/etc/ssh/sshd_config.d/50-sftp-monitoring.conf`):
```text
# Global SSH & SFTP Verbose Auditing for ALL Linux Users (existing and newly created)
LogLevel VERBOSE
SyslogFacility AUTHPRIV
Subsystem sftp internal-sftp -f AUTHPRIV -l INFO -u 0022

# 1. Block SFTP and SSH shell access for restricted VNC-only users in 'sftp-denied'
Match Group sftp-denied
    ForceCommand /usr/bin/false
    AllowTcpForwarding no
    X11Forwarding no

# 2. Allow SFTP-only file transfers (no interactive SSH shell) for users in 'sftp-allowed'
Match Group sftp-allowed
    ForceCommand internal-sftp -f AUTHPRIV -l INFO -u 0022
    AllowTcpForwarding no
    X11Forwarding no
```

#### Commands:
```bash
# 1. Back up existing SSH configurations
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
[ -f /etc/ssh/sshd_config.d/50-sftp-monitoring.conf ] && \
  sudo cp /etc/ssh/sshd_config.d/50-sftp-monitoring.conf /etc/ssh/sshd_config.d/50-sftp-monitoring.conf.bak

# 2. Ensure SFTP access control groups exist
sudo groupadd -f sftp-allowed
sudo groupadd -f sftp-denied

# 3. Comment out any Subsystem sftp definitions in main sshd_config or other drop-in files
sudo sed -i 's/^[[:space:]]*Subsystem[[:space:]]\+sftp/#Subsystem sftp/g' /etc/ssh/sshd_config
for f in /etc/ssh/sshd_config.d/*.conf; do
  if [ "$f" != "/etc/ssh/sshd_config.d/50-sftp-monitoring.conf" ] && [ -f "$f" ]; then
    sudo sed -i 's/^[[:space:]]*Subsystem[[:space:]]\+sftp/#Subsystem sftp/g' "$f"
  fi
done

# 4. Write the global SSH/SFTP monitoring configuration
sudo tee /etc/ssh/sshd_config.d/50-sftp-monitoring.conf << 'EOF'
# Global SSH & SFTP Verbose Auditing for ALL Linux Users (existing and newly created)
LogLevel VERBOSE
SyslogFacility AUTHPRIV
Subsystem sftp internal-sftp -f AUTHPRIV -l INFO -u 0022

# 1. Block SFTP and SSH shell access for restricted VNC-only users in 'sftp-denied'
Match Group sftp-denied
    ForceCommand /usr/bin/false
    AllowTcpForwarding no
    X11Forwarding no

# 2. Allow SFTP-only file transfers (no interactive SSH shell) for users in 'sftp-allowed'
Match Group sftp-allowed
    ForceCommand internal-sftp -f AUTHPRIV -l INFO -u 0022
    AllowTcpForwarding no
    X11Forwarding no
EOF

# 5. Validate SSHD configuration and reload
sudo sshd -t && sudo systemctl reload sshd
```

#### Validation:
```bash
sudo sshd -T | grep -E "^loglevel|^syslogfacility|^subsystem"
sudo sshd -T -C user=ec2-user | grep -E "^loglevel|^subsystem"
```

#### Expected Result:
Both commands output `loglevel VERBOSE`, `syslogfacility AUTHPRIV`, and `subsystem sftp internal-sftp -f AUTHPRIV -l INFO -u 0022`.

---

### Step 5: Configure Kernel `auditd` Rules for All Users, Account Management & VNC Changes
* **Server:** Wazuh Agent (`vnc-server` — `172.31.15.219`, RHEL 9.8)
* **File Modified:** `/etc/audit/rules.d/wazuh-full-monitoring.rules`

#### Commands:
```bash
# 1. Back up existing audit rules and pre-create watched directories
[ -f /etc/audit/rules.d/wazuh-full-monitoring.rules ] && \
  sudo cp /etc/audit/rules.d/wazuh-full-monitoring.rules /etc/audit/rules.d/wazuh-full-monitoring.rules.bak
sudo rm -f /etc/audit/rules.d/wazuh-command-audit.rules
sudo mkdir -p /etc/tigervnc /etc/firewalld /etc/NetworkManager/system-connections /etc/ssh/sshd_config.d

# 2. Write comprehensive auditd rules covering all UIDs >= 1000, user/group changes, SSHD, and VNC
sudo tee /etc/audit/rules.d/wazuh-full-monitoring.rules << 'EOF'
-D
-b 8192

## 1. Track ALL commands executed by any human user (auid >= 1000) including sudo/root escalations
-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=-1 -k audit-wazuh-c
-a always,exit -F arch=b32 -S execve -F auid>=1000 -F auid!=-1 -k audit-wazuh-c

## 2. Track Linux user creation, deletion, password changes, and group membership modifications
-w /etc/passwd -p wa -k user-modify
-w /etc/shadow -p wa -k user-modify
-w /etc/group -p wa -k group-modify
-w /etc/gshadow -p wa -k group-modify
-w /etc/security/opasswd -p wa -k user-modify

## 3. Track TigerVNC configuration and service changes
-w /etc/tigervnc/ -p wa -k vnc-config-modify
-w /etc/pam.d/tigervnc -p wa -k vnc-config-modify

## 4. Track SSH/SFTP access permission & daemon configuration changes
-w /etc/ssh/sshd_config -p wa -k sshd-config-modify
-w /etc/ssh/sshd_config.d/ -p wa -k sshd-config-modify

## 5. Track Network & Firewall configuration changes
-w /etc/firewalld/ -p wa -k network-config-modify
-w /etc/NetworkManager/system-connections/ -p wa -k network-config-modify
-w /etc/hosts -p wa -k network-config-modify
-w /etc/resolv.conf -p wa -k network-config-modify
EOF

sudo augenrules --load
```

#### Validation:
```bash
sudo auditctl -l
```

#### Expected Result:
Outputs all 15 kernel audit rules with zero errors.

---

### Step 6: Update Agent `/var/ossec/etc/ossec.conf` to Collect `/var/log/secure`, `/var/log/audit/audit.log`, and VNC Logs (`/home/*/.vnc/*.log`)
* **Server:** Wazuh Agent (`vnc-server` — `172.31.15.219`, RHEL 9.8)
* **File Modified:** `/var/ossec/etc/ossec.conf`

*(Note: By removing duplicate `journald` collection of `sshd` events and collecting `/var/log/secure`, `/var/log/audit/audit.log`, `/var/log/messages`, and `/home/*/.vnc/*.log`, Wazuh Agent processes every SSH/SFTP event once without double-counting brute-force frequency counters!)*

#### Commands:
```bash
# 1. Back up existing Agent ossec.conf
sudo cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak

# 2. Write clean, complete Agent ossec.conf (automatically preserves 172.31.12.109 from existing config)
CURRENT_MANAGER_IP=$(sudo sed -n 's/.*<address>\(.*\)<\/address>.*/\1/p' /var/ossec/etc/ossec.conf.bak | head -n 1)
[ -z "$CURRENT_MANAGER_IP" ] && CURRENT_MANAGER_IP="172.31.12.109"

sudo tee /var/ossec/etc/ossec.conf << EOF
<ossec_config>
  <client>
    <server>
      <address>${CURRENT_MANAGER_IP}</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <config-profile>rhel, rhel9, rhel9.8</config-profile>
    <notify_time>10</notify_time>
    <time-reconnect>60</time-reconnect>
    <auto_restart>yes</auto_restart>
    <crypto_method>aes</crypto_method>
  </client>

  <client_buffer>
    <disabled>no</disabled>
    <queue_size>5000</queue_size>
    <events_per_second>500</events_per_second>
  </client_buffer>

  <rootcheck>
    <disabled>no</disabled>
    <check_files>yes</check_files>
    <check_trojans>yes</check_trojans>
    <check_dev>yes</check_dev>
    <check_sys>yes</check_sys>
    <check_pids>yes</check_pids>
    <check_ports>yes</check_ports>
    <check_if>yes</check_if>
    <frequency>43200</frequency>
    <rootkit_files>etc/shared/rootkit_files.txt</rootkit_files>
    <rootkit_trojans>etc/shared/rootkit_trojans.txt</rootkit_trojans>
    <skip_nfs>yes</skip_nfs>
    <ignore>/var/lib/containerd</ignore>
    <ignore>/var/lib/docker/overlay2</ignore>
  </rootcheck>

  <wodle name="syscollector">
    <disabled>no</disabled>
    <interval>1h</interval>
    <scan_on_start>yes</scan_on_start>
    <hardware>yes</hardware>
    <os>yes</os>
    <network>yes</network>
    <packages>yes</packages>
    <ports all="yes">yes</ports>
    <processes>yes</processes>
    <users>yes</users>
    <groups>yes</groups>
    <services>yes</services>
    <browser_extensions>yes</browser_extensions>
    <synchronization>
      <max_eps>10</max_eps>
    </synchronization>
  </wodle>

  <sca>
    <enabled>yes</enabled>
    <scan_on_start>yes</scan_on_start>
    <interval>12h</interval>
    <skip_nfs>yes</skip_nfs>
  </sca>

  <syscheck>
    <disabled>no</disabled>
    <frequency>43200</frequency>
    <scan_on_start>yes</scan_on_start>
    <alert_new_files>yes</alert_new_files>
    <auto_ignore frequency="10" timeframe="3600">no</auto_ignore>

    <directories check_all="yes" whodata="yes" report_changes="yes">/etc,/usr/bin,/usr/sbin</directories>
    <directories check_all="yes" whodata="yes">/boot,/home,/root</directories>

    <ignore>/etc/mtab</ignore>
    <ignore>/etc/hosts.deny</ignore>
    <ignore>/etc/mail/statistics</ignore>
    <ignore>/etc/random-seed</ignore>
    <ignore>/etc/random.seed</ignore>
    <ignore>/etc/adjtime</ignore>
    <ignore>/etc/httpd/logs</ignore>
    <ignore>/etc/utmpx</ignore>
    <ignore>/etc/wtmpx</ignore>
    <ignore>/etc/cups/certs</ignore>
    <ignore>/etc/dumpdates</ignore>
    <ignore>/etc/svc/volatile</ignore>
    <ignore type="sregex">.log$|.swp$</ignore>

    <nodiff>/etc/ssl/private.key</nodiff>
    <nodiff>/etc/shadow</nodiff>
    <nodiff>/etc/shadow-</nodiff>
    <nodiff>/etc/gshadow</nodiff>
    <nodiff>/etc/gshadow-</nodiff>

    <skip_nfs>yes</skip_nfs>
    <skip_dev>yes</skip_dev>
    <skip_proc>yes</skip_proc>
    <skip_sys>yes</skip_sys>
    <process_priority>10</process_priority>
    <max_eps>50</max_eps>
    <synchronization>
      <enabled>yes</enabled>
      <interval>5m</interval>
      <max_eps>10</max_eps>
    </synchronization>
  </syscheck>

  <localfile>
    <log_format>command</log_format>
    <command>df -P</command>
    <frequency>360</frequency>
  </localfile>

  <localfile>
    <log_format>full_command</log_format>
    <command>netstat -tulpn | sed 's/\([[:alnum:]]\+\)\ \+[[:digit:]]\+\ \+[[:digit:]]\+\ \+\(.*\):\([[:digit:]]*\)\ \+\([0-9\.\:\*]\+\).\+\ \([[:digit:]]*\/[[:alnum:]\-]*\).*/\1 \2 == \3 == \4 \5/' | sort -k 4 -g | sed 's/ == \(.*\) ==/:\1/' | sed 1,2d</command>
    <alias>netstat listening ports</alias>
    <frequency>360</frequency>
  </localfile>

  <localfile>
    <log_format>full_command</log_format>
    <command>ss -tulpnH | awk '{print \$1, \$5}' | sort -u</command>
    <alias>active listening sockets</alias>
    <frequency>60</frequency>
  </localfile>

  <localfile>
    <log_format>full_command</log_format>
    <command>last -n 20</command>
    <frequency>360</frequency>
  </localfile>

  <localfile>
    <log_format>audit</log_format>
    <location>/var/log/audit/audit.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/secure</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/messages</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/home/*/.vnc/*.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/ossec/logs/active-responses.log</location>
  </localfile>

  <active-response>
    <disabled>no</disabled>
    <ca_store>etc/wpk_root.pem</ca_store>
    <ca_verification>yes</ca_verification>
  </active-response>

  <logging>
    <log_format>plain</log_format>
  </logging>
</ossec_config>
EOF

sudo chown root:wazuh /var/ossec/etc/ossec.conf
sudo chmod 660 /var/ossec/etc/ossec.conf
sudo systemctl restart wazuh-agent
```

#### Validation:
```bash
sudo systemctl status wazuh-agent --no-pager
sudo grep -E "Analyzing file.*secure|Analyzing file.*audit" /var/ossec/logs/ossec.log | tail -n 5
```

#### Expected Result:
`wazuh-agent` is `active (running)` and `ossec.log` confirms `/var/log/secure` and `/var/log/audit/audit.log` are being actively analyzed.

---

## 5. Phase 2 of Fix: Updated Custom Decoders & Multi-Tier Rules on Wazuh Manager (`wazuh-server`)

Execute Steps 7, 8, and 9 on the **Wazuh Manager (`wazuh-server` — `172.31.12.109`)**.

### Step 7: Update `/var/ossec/etc/decoders/sftp_decoders.xml` for All SFTP Operations, Blocked Users & VNC
* **Server:** Wazuh Manager (`wazuh-server` — `172.31.12.109`, RHEL 9.8)
* **File Modified:** `/var/ossec/etc/decoders/sftp_decoders.xml`

#### What This Decoder Update Adds:
1. Decodes `session opened for local user <dstuser> from [<srcip>]` and `session closed for local user <dstuser>` under both `sshd` and `sftp-server`.
2. Decodes `open "/home/<dstuser>/<file>" flags <extra_data>` AND `open "<file>" flags <extra_data>` so that whenever a file inside `/home/<username>/...` is uploaded or downloaded, **`dstuser` is extracted directly from the file path** even when OpenSSH omits the username on the `open` log line!
3. Decodes `close "<file>" bytes read <status> written <extra_data>` to distinguish **SFTP Transfer Completed** from a mere file open attempt.
4. Decodes `remove name "<file>"`, `rmdir name "<file>"`, and `rename old "<file>" new "<extra_data>"`.
5. Decodes `Starting session: forced-command (config) '/usr/bin/false' for <dstuser> from <srcip> port <srcport>` when a restricted user in `sftp-denied` is blocked.
6. Decodes `Xvnc` / TigerVNC authentication events.

#### Configuration & Commands:
```bash
# 1. Back up existing decoder file
[ -f /var/ossec/etc/decoders/sftp_decoders.xml ] && \
  sudo cp /var/ossec/etc/decoders/sftp_decoders.xml /var/ossec/etc/decoders/sftp_decoders.xml.bak

# 2. Write complete PCRE2 SFTP & VNC decoders
sudo tee /var/ossec/etc/decoders/sftp_decoders.xml << 'EOF'
<decoder name="sftp-server">
  <program_name>^sftp-server|^internal-sftp</program_name>
</decoder>

<!-- 1. SFTP Session Opened / Closed under sftp-server -->
<decoder name="sftp-server-session">
  <parent>sftp-server</parent>
  <prematch type="pcre2">^session opened for local user </prematch>
  <regex type="pcre2">^session opened for local user (\S+) from \[(\S+)\]</regex>
  <order>dstuser, srcip</order>
</decoder>

<decoder name="sftp-server-session-close">
  <parent>sftp-server</parent>
  <prematch type="pcre2">^session closed for local user </prematch>
  <regex type="pcre2">^session closed for local user (\S+)</regex>
  <order>dstuser</order>
</decoder>

<!-- 2. SFTP File Open (extracts dstuser automatically if path is /home/<user>/...) -->
<decoder name="sftp-server-file-home">
  <parent>sftp-server</parent>
  <prematch type="pcre2">^open "/home/</prematch>
  <regex type="pcre2">^open "(/home/([^/"]+)/[^"]*)" flags (\S+) mode</regex>
  <order>file, dstuser, extra_data</order>
</decoder>

<decoder name="sftp-server-file">
  <parent>sftp-server</parent>
  <prematch type="pcre2">^open "</prematch>
  <regex type="pcre2">^open "([^"]+)" flags (\S+) mode</regex>
  <order>file, extra_data</order>
</decoder>

<!-- 3. SFTP File Close (Transfer Completed with bytes read/written) -->
<decoder name="sftp-server-close-home">
  <parent>sftp-server</parent>
  <prematch type="pcre2">^close "/home/</prematch>
  <regex type="pcre2">^close "(/home/([^/"]+)/[^"]*)" bytes read (\d+) written (\d+)</regex>
  <order>file, dstuser, status, extra_data</order>
</decoder>

<decoder name="sftp-server-close">
  <parent>sftp-server</parent>
  <prematch type="pcre2">^close "</prematch>
  <regex type="pcre2">^close "([^"]+)" bytes read (\d+) written (\d+)</regex>
  <order>file, status, extra_data</order>
</decoder>

<!-- 4. SFTP Delete / Rename / Setstat under sftp-server -->
<decoder name="sftp-server-modify-home">
  <parent>sftp-server</parent>
  <prematch type="pcre2">^(?:remove|rmdir|setstat) name "/home/|^rename old "/home/</prematch>
  <regex type="pcre2">^(?:remove name|rmdir name|setstat name|rename old) "(/home/([^/"]+)/[^"]*)"</regex>
  <order>file, dstuser</order>
</decoder>

<decoder name="sftp-server-modify">
  <parent>sftp-server</parent>
  <prematch type="pcre2">^(?:remove|rmdir|setstat) name "|^rename old "</prematch>
  <regex type="pcre2">^(?:remove name|rmdir name|setstat name|rename old) "([^"]+)"</regex>
  <order>file</order>
</decoder>

<!-- 5. Same SFTP Decoders when logged under parent 'sshd' (RHEL 9 internal-sftp default) -->
<decoder name="sshd-sftp-session">
  <parent>sshd</parent>
  <prematch type="pcre2">^session opened for local user </prematch>
  <regex type="pcre2">^session opened for local user (\S+) from \[(\S+)\]</regex>
  <order>dstuser, srcip</order>
</decoder>

<decoder name="sshd-sftp-session-close">
  <parent>sshd</parent>
  <prematch type="pcre2">^session closed for local user </prematch>
  <regex type="pcre2">^session closed for local user (\S+)</regex>
  <order>dstuser</order>
</decoder>

<decoder name="sshd-sftp-file-home">
  <parent>sshd</parent>
  <prematch type="pcre2">^open "/home/</prematch>
  <regex type="pcre2">^open "(/home/([^/"]+)/[^"]*)" flags (\S+) mode</regex>
  <order>file, dstuser, extra_data</order>
</decoder>

<decoder name="sshd-sftp-file">
  <parent>sshd</parent>
  <prematch type="pcre2">^open "</prematch>
  <regex type="pcre2">^open "([^"]+)" flags (\S+) mode</regex>
  <order>file, extra_data</order>
</decoder>

<decoder name="sshd-sftp-close-home">
  <parent>sshd</parent>
  <prematch type="pcre2">^close "/home/</prematch>
  <regex type="pcre2">^close "(/home/([^/"]+)/[^"]*)" bytes read (\d+) written (\d+)</regex>
  <order>file, dstuser, status, extra_data</order>
</decoder>

<decoder name="sshd-sftp-close">
  <parent>sshd</parent>
  <prematch type="pcre2">^close "</prematch>
  <regex type="pcre2">^close "([^"]+)" bytes read (\d+) written (\d+)</regex>
  <order>file, status, extra_data</order>
</decoder>

<decoder name="sshd-sftp-modify-home">
  <parent>sshd</parent>
  <prematch type="pcre2">^(?:remove|rmdir|setstat) name "/home/|^rename old "/home/</prematch>
  <regex type="pcre2">^(?:remove name|rmdir name|setstat name|rename old) "(/home/([^/"]+)/[^"]*)"</regex>
  <order>file, dstuser</order>
</decoder>

<decoder name="sshd-sftp-modify">
  <parent>sshd</parent>
  <prematch type="pcre2">^(?:remove|rmdir|setstat) name "|^rename old "</prematch>
  <regex type="pcre2">^(?:remove name|rmdir name|setstat name|rename old) "([^"]+)"</regex>
  <order>file</order>
</decoder>

<!-- 6. Blocked SFTP User Decoder (Match Group sftp-denied -> forced-command '/usr/bin/false') -->
<decoder name="sshd-sftp-blocked">
  <parent>sshd</parent>
  <prematch type="pcre2">forced-command \(config\) '/usr/bin/false'</prematch>
  <regex type="pcre2">forced-command \(config\) '/usr/bin/false' for (\S+) from (\S+) port (\d+)</regex>
  <order>dstuser, srcip, srcport</order>
</decoder>
EOF

sudo chown wazuh:wazuh /var/ossec/etc/decoders/sftp_decoders.xml
sudo chmod 660 /var/ossec/etc/decoders/sftp_decoders.xml
```

#### Validation:
```bash
sudo /var/ossec/bin/wazuh-analysisd -t
```

#### Expected Result:
`wazuh-analysisd -t` returns `0` with no errors.

---

### Step 8: Update `/var/ossec/etc/rules/sftp_and_vnc_rules.xml` (Separating SFTP Connection, Attempt, Completion, Denial & VNC)
* **Server:** Wazuh Manager (`wazuh-server` — `172.31.12.109`, RHEL 9.8)
* **File Modified:** `/var/ossec/etc/rules/sftp_and_vnc_rules.xml`

#### Complete SFTP & VNC Rule Matrix

| Rule ID | Rule Name / Scenario | Level | Category Group Tag | Default Email |
| :--- | :--- | :--- | :--- | :--- |
| **100501** | SFTP Session Opened (Connection established, no file transferred yet) | `5` | `notify_sftp_connect` | **Disabled** |
| **100511** | SFTP Session Closed | `3` | `notify_sftp_connect` | **Disabled** |
| **100502** | SFTP File Upload Attempt (`open` with `WRITE`/`CREATE`/`TRUNCATE`/`APPEND`) | `8` | `notify_sftp_transfer` | **Enabled (Medium)** |
| **100503** | SFTP File Download Detected (`open` with `READ`) | `8` | `notify_sftp_transfer` | **Enabled (Medium)** |
| **100507** | SFTP File Upload/Download Transfer Completed (`close` with bytes written/read) | `8` | `notify_sftp_transfer` | **Enabled (Medium)** |
| **100504** | SFTP File Deleted, Renamed, or Permission Modified (`remove`, `rmdir`, `rename`) | `10` | `notify_sftp_transfer` | **Enabled (Medium)** |
| **100505** | SFTP Access Denied for Restricted User (`sftp-denied` group / `ForceCommand /usr/bin/false`) | `12` | `notify_sftp_denied` | **Enabled (High)** |
| **100508** | SFTP File Transfer / Operation Failed (`sent status Permission denied` or `Failure`) | `11` | `notify_sftp_denied` | **Enabled (High)** |
| **100506** | TigerVNC Configuration Modified (`audit.key: vnc-config-modify`) | `10` | `notify_vnc` | **Disabled** |
| **100509** | TigerVNC Session Opened / User Authenticated | `5` | `notify_vnc` | **Disabled** |
| **100510** | TigerVNC Authentication Failed | `8` | `notify_vnc` | **Disabled** |

#### Configuration & Commands:
```bash
# 1. Back up existing SFTP/VNC rules file
[ -f /var/ossec/etc/rules/sftp_and_vnc_rules.xml ] && \
  sudo cp /var/ossec/etc/rules/sftp_and_vnc_rules.xml /var/ossec/etc/rules/sftp_and_vnc_rules.xml.bak

# 2. Write the updated SFTP and VNC rules
sudo tee /var/ossec/etc/rules/sftp_and_vnc_rules.xml << 'EOF'
<group name="sftp_monitoring,">

  <!-- 1. SFTP Session Opened & Closed (Connection only - NOT a file transfer) -->
  <rule id="100501" level="5">
    <match>session opened for local user</match>
    <description>SFTP Connection: Session opened by user $(dstuser) from IP $(srcip)</description>
    <group>authentication_success,sftp_session,notify_sftp_connect,</group>
  </rule>

  <rule id="100511" level="3">
    <match>session closed for local user</match>
    <description>SFTP Connection: Session closed for user $(dstuser)</description>
    <group>sftp_session,notify_sftp_connect,</group>
  </rule>

  <!-- 2. SFTP File Upload Attempt (Open with Write/Create/Truncate/Append flags) -->
  <rule id="100502" level="8">
    <match>flags WRITE|flags CREATE|flags TRUNCATE|flags APPEND|flags READ,WRITE</match>
    <description>SFTP File Transfer Detected (Upload Attempt): File "$(file)" opened by $(dstuser) with flags $(extra_data)</description>
    <group>syscheck,sftp_transfer,sftp_upload,notify_sftp_transfer,</group>
  </rule>

  <!-- 3. SFTP File Download Attempt (Open with Read flag) -->
  <rule id="100503" level="8">
    <match>flags READ mode</match>
    <description>SFTP File Transfer Detected (Download): File "$(file)" downloaded by $(dstuser)</description>
    <group>sftp_transfer,sftp_download,notify_sftp_transfer,</group>
  </rule>

  <!-- 4. SFTP File Transfer Completed (Close after bytes written or read > 0) -->
  <rule id="100507" level="8">
    <regex type="pcre2">^close "[^"]+" bytes read (?:[1-9]\d* written \d+|0 written [1-9]\d*)</regex>
    <description>SFTP File Transfer Completed: File "$(file)" closed (Bytes read: $(status), Bytes written: $(extra_data))</description>
    <group>sftp_transfer,sftp_completed,notify_sftp_transfer,</group>
  </rule>

  <!-- 5. SFTP File Deleted, Renamed, or Permission Modified -->
  <rule id="100504" level="10">
    <regex>remove name "|rmdir name "|rename old "|setstat name "</regex>
    <description>SFTP File Modification/Delete/Rename Detected on "$(file)"</description>
    <group>syscheck,sftp_transfer,sftp_delete_rename,notify_sftp_transfer,</group>
  </rule>

  <!-- 6. SFTP Access Denied for Restricted User (sftp-denied group) -->
  <rule id="100505" level="12">
    <if_group>sshd</if_group>
    <match>Forced command '/usr/bin/false'|forced-command (config) '/usr/bin/false'|subsystem request for sftp failed</match>
    <description>SFTP Access Denied: Restricted user $(dstuser) from IP $(srcip) attempted SFTP access</description>
    <group>authentication_failed,sftp_denied,notify_sftp_denied,</group>
  </rule>

  <!-- 7. SFTP File Operation / Transfer Failed (Permission denied or Failure status) -->
  <rule id="100508" level="11">
    <match>sent status Permission denied|sent status Failure|sent status No such file</match>
    <description>SFTP File Operation Failed/Denied: SFTP server returned error status</description>
    <group>sftp_denied,sftp_operation_failed,notify_sftp_denied,</group>
  </rule>

  <!-- 8. TigerVNC Configuration & Session Monitoring -->
  <rule id="100506" level="10">
    <if_sid>80700</if_sid>
    <field name="audit.key">vnc-config-modify</field>
    <description>VNC Configuration Modified by user AUID $(audit.auid)</description>
    <group>vnc_monitoring,notify_vnc,</group>
  </rule>

  <rule id="100509" level="5">
    <match>pam_unix(tigervnc:session): session opened|Connections: accepted:</match>
    <description>VNC Session Opened on server</description>
    <group>authentication_success,vnc_monitoring,notify_vnc,</group>
  </rule>

  <rule id="100510" level="8">
    <match>pam_unix(tigervnc:auth): authentication failure|AuthFailureException|Authentication failure</match>
    <description>VNC Authentication Failed on server</description>
    <group>authentication_failed,vnc_monitoring,notify_vnc,</group>
  </rule>

</group>
EOF

sudo chown wazuh:wazuh /var/ossec/etc/rules/sftp_and_vnc_rules.xml
sudo chmod 660 /var/ossec/etc/rules/sftp_and_vnc_rules.xml
```

---

### Step 9: Update `/var/ossec/etc/rules/ssh_and_network_rules.xml` (5-Attempt Medium & 10-Attempt High Brute-Force + User/Group Management)
* **Server:** Wazuh Manager (`wazuh-server` — `172.31.12.109`, RHEL 9.8)
* **File Modified:** `/var/ossec/etc/rules/ssh_and_network_rules.xml`

#### How 5-Attempt (`[MEDIUM]`) and 10-Attempt (`[HIGH]`) Brute-Force Coexist Cleanly:
* **Rules `100611` & `100612` (High Severity — Level 12, `frequency="10"`, `timeframe="300"`):** Placed **first** in the rule file so when the 10th failed SSH attempt within 5 minutes occurs (tracked by `<same_source_ip />` or `<same_user />`), Wazuh matches the High-Severity rule immediately.
* **Rules `100601` & `100602` (Medium Severity — Level 8, `frequency="5"`, `timeframe="300"`):** Placed right below `100611`/`100612` and tagged with `<group>authentication_failed,...</group>` so event #5 triggers the Medium-Severity alert while still remaining part of the `authentication_failed` correlation group for events #6–#10!

#### Configuration & Commands:
```bash
# 1. Back up existing SSH/Network rules file
[ -f /var/ossec/etc/rules/ssh_and_network_rules.xml ] && \
  sudo cp /var/ossec/etc/rules/ssh_and_network_rules.xml /var/ossec/etc/rules/ssh_and_network_rules.xml.bak

# 2. Write the updated SSH, Brute-Force, User/Group Management, and Network rules
sudo tee /var/ossec/etc/rules/ssh_and_network_rules.xml << 'EOF'
<group name="ssh_security_monitoring,network_security_monitoring,">

  <!-- ========================================================================= -->
  <!-- HIGH SEVERITY: 10 Failed SSH Attempts Within 5 Minutes (300s)             -->
  <!-- Evaluated BEFORE the 5-attempt rule so attempt #10 triggers HIGH severity -->
  <!-- ========================================================================= -->
  <rule id="100611" level="12" frequency="10" timeframe="300">
    <if_matched_group>authentication_failed</if_matched_group>
    <same_source_ip />
    <description>SSH Brute-Force Attack Detected: 10 failed login attempts within 5 minutes from IP $(srcip) (target user: $(dstuser))</description>
    <mitre>
      <id>T1110.001</id>
    </mitre>
    <group>authentication_failed,authentication_failures,ssh_brute_force_high,notify_ssh_bruteforce,</group>
  </rule>

  <rule id="100612" level="12" frequency="10" timeframe="300">
    <if_matched_group>authentication_failed</if_matched_group>
    <same_user />
    <description>SSH Brute-Force Attack Detected: 10 failed login attempts within 5 minutes targeting user $(dstuser) (from IP $(srcip))</description>
    <mitre>
      <id>T1110.001</id>
    </mitre>
    <group>authentication_failed,authentication_failures,ssh_brute_force_high,notify_ssh_bruteforce,</group>
  </rule>

  <!-- ========================================================================= -->
  <!-- MEDIUM SEVERITY: 5 Failed SSH Attempts Within 5 Minutes (300s)            -->
  <!-- Includes 'authentication_failed' group so events 5-9 continue counting    -->
  <!-- ========================================================================= -->
  <rule id="100601" level="8" frequency="5" timeframe="300">
    <if_matched_group>authentication_failed</if_matched_group>
    <same_source_ip />
    <description>SSH Brute-Force Activity Detected: 5 failed login attempts within 5 minutes from IP $(srcip) (target user: $(dstuser))</description>
    <mitre>
      <id>T1110.001</id>
    </mitre>
    <group>authentication_failed,authentication_failures,ssh_brute_force_medium,notify_ssh_bruteforce,</group>
  </rule>

  <rule id="100602" level="8" frequency="5" timeframe="300">
    <if_matched_group>authentication_failed</if_matched_group>
    <same_user />
    <description>SSH Brute-Force Activity Detected: 5 failed login attempts within 5 minutes targeting user $(dstuser) (from IP $(srcip))</description>
    <mitre>
      <id>T1110.001</id>
    </mitre>
    <group>authentication_failed,authentication_failures,ssh_brute_force_medium,notify_ssh_bruteforce,</group>
  </rule>

  <!-- ========================================================================= -->
  <!-- SUSPICIOUS SSH LOGINS (Configurable Email Category: notify_ssh_suspicious)-->
  <!-- ========================================================================= -->
  <rule id="100603" level="11" frequency="2" timeframe="300">
    <if_matched_sid>5715</if_matched_sid>
    <same_user />
    <different_srcip />
    <description>Suspicious Concurrent SSH Access: User $(dstuser) logged in from multiple different IP addresses within 5 minutes (latest IP: $(srcip))</description>
    <mitre>
      <id>T1078</id>
    </mitre>
    <group>authentication_success,ssh_multi_ip,notify_ssh_suspicious,</group>
  </rule>

  <rule id="100604" level="12" frequency="4" timeframe="300">
    <if_matched_group>authentication_failed</if_matched_group>
    <same_source_ip />
    <different_user />
    <description>SSH Username Enumeration / Spraying Detected: Source IP $(srcip) failed authentication against multiple distinct usernames within 5 minutes (latest user: $(dstuser))</description>
    <mitre>
      <id>T1110.003</id>
    </mitre>
    <group>authentication_failures,ssh_enumeration,notify_ssh_suspicious,</group>
  </rule>

  <rule id="100605" level="14" timeframe="300">
    <if_sid>5715</if_sid>
    <if_matched_group>notify_ssh_bruteforce</if_matched_group>
    <same_source_ip />
    <description>CRITICAL: Successful SSH login by user $(dstuser) from IP $(srcip) immediately following an SSH brute-force attack</description>
    <mitre>
      <id>T1110</id>
      <id>T1078</id>
    </mitre>
    <group>authentication_success,ssh_compromise_indicator,notify_ssh_suspicious,</group>
  </rule>

  <rule id="100606" level="12">
    <if_sid>5715</if_sid>
    <user>^root$</user>
    <description>Direct Root SSH Login Succeeded from IP $(srcip) port $(srcport)</description>
    <mitre>
      <id>T1078.003</id>
    </mitre>
    <group>authentication_success,root_ssh_login,notify_ssh_suspicious,</group>
  </rule>

  <rule id="100607" level="10">
    <if_group>authentication_failed</if_group>
    <user>^root$</user>
    <description>Direct Root SSH Login Attempt Failed from IP $(srcip)</description>
    <mitre>
      <id>T1078.003</id>
    </mitre>
    <group>authentication_failed,root_ssh_login,notify_ssh_suspicious,</group>
  </rule>

  <rule id="100608" level="11">
    <if_sid>5715</if_sid>
    <srcip>!10.0.0.0/8</srcip>
    <srcip>!11.0.0.0/8</srcip>
    <srcip>!172.16.0.0/12</srcip>
    <srcip>!192.168.0.0/16</srcip>
    <srcip>!127.0.0.0/8</srcip>
    <description>Suspicious External SSH Login: User $(dstuser) authenticated from non-private external IP $(srcip)</description>
    <mitre>
      <id>T1078</id>
    </mitre>
    <group>authentication_success,external_ssh_login,notify_ssh_suspicious,</group>
  </rule>

  <rule id="100609" level="10">
    <if_sid>5715</if_sid>
    <time>22:00 - 06:00</time>
    <description>Off-Hours SSH Login Detected: User $(dstuser) logged in from IP $(srcip) outside normal maintenance hours (22:00-06:00)</description>
    <group>authentication_success,off_hours_ssh,notify_ssh_suspicious,</group>
  </rule>

  <rule id="100610" level="12">
    <if_sid>80700</if_sid>
    <field name="audit.key">sshd-config-modify</field>
    <description>SSH Daemon Configuration Modified: $(audit.file.name) modified by user AUID $(audit.auid)</description>
    <mitre>
      <id>T1098</id>
    </mitre>
    <group>sshd_config_change,notify_ssh_suspicious,</group>
  </rule>

  <!-- ========================================================================= -->
  <!-- LINUX USER & GROUP MANAGEMENT MONITORING                                  -->
  <!-- ========================================================================= -->
  <rule id="100630" level="8">
    <if_sid>80700</if_sid>
    <field name="audit.key">user-modify</field>
    <description>Linux User Account Database Modified: $(audit.file.name) changed by AUID $(audit.auid) via $(audit.exe)</description>
    <group>account_management,notify_user_mgmt,</group>
  </rule>

  <rule id="100631" level="8">
    <if_sid>80700</if_sid>
    <field name="audit.key">group-modify</field>
    <description>Linux Group Membership Modified: $(audit.file.name) changed by AUID $(audit.auid) via $(audit.exe)</description>
    <group>group_management,notify_group_mgmt,</group>
  </rule>

  <!-- ========================================================================= -->
  <!-- NETWORK PORT & FIREWALL ACTIVITY                                          -->
  <!-- ========================================================================= -->
  <rule id="100620" level="10">
    <if_sid>530</if_sid>
    <match>^ossec: output: 'active listening sockets'</match>
    <check_diff />
    <description>Network Port Change Detected: Active TCP/UDP listening sockets changed on server</description>
    <mitre>
      <id>T1049</id>
    </mitre>
    <group>network_port_change,notify_other,</group>
  </rule>

  <rule id="100621" level="11">
    <if_sid>80700</if_sid>
    <field name="audit.key">network-config-modify</field>
    <description>Firewall or Network Configuration Modified: $(audit.file.name) changed by user AUID $(audit.auid)</description>
    <mitre>
      <id>T1562.004</id>
    </mitre>
    <group>firewall_config_change,notify_other,</group>
  </rule>

  <rule id="100622" level="7">
    <match>FINAL_REJECT:|HOST_REJECT:</match>
    <description>Firewall Blocked Inbound Connection Attempt</description>
    <group>firewall_drop,</group>
  </rule>

  <rule id="100623" level="11" frequency="5" timeframe="120">
    <if_matched_sid>100622</if_matched_sid>
    <same_source_ip />
    <description>Suspicious Port Scan / Repeated Blocked Connections: 5 firewall drops within 2 minutes from IP $(srcip)</description>
    <mitre>
      <id>T1046</id>
    </mitre>
    <group>firewall_drop,port_scan_detected,notify_other,</group>
  </rule>

</group>
EOF

sudo chown wazuh:wazuh /var/ossec/etc/rules/ssh_and_network_rules.xml
sudo chmod 660 /var/ossec/etc/rules/ssh_and_network_rules.xml
```

#### Validation:
```bash
sudo /var/ossec/bin/wazuh-analysisd -t
```

#### Expected Result:
`wazuh-analysisd -t` returns `0` with no errors.

---

## 6. Phase 3 of Fix: Configurable Notification Policy & Redesigned 6-Section HTML Email Engine

### Step 10: Create the Centralized Email Notification Policy File (`/var/ossec/etc/email_notification_policy.json`)
* **Server:** Wazuh Manager (`wazuh-server` — `172.31.12.109`, RHEL 9.8)
* **File Created:** `/var/ossec/etc/email_notification_policy.json`

#### Configuration & Commands:
```bash
sudo tee /var/ossec/etc/email_notification_policy.json << 'EOF'
{
  "categories": {
    "sftp_successful_transfers": true,
    "sftp_failed_denied_operations": true,
    "ssh_bruteforce_detection": true,
    "sftp_connection_attempts": false,
    "ssh_authentication_events": false,
    "ssh_suspicious_login": false,
    "linux_user_creation_deletion": false,
    "linux_group_changes": false,
    "vnc_session_events": false,
    "file_integrity_monitoring": false,
    "other_security_alerts": false
  },
  "deduplication_window_seconds": 290
}
EOF

sudo chown root:wazuh /var/ossec/etc/email_notification_policy.json
sudo chmod 660 /var/ossec/etc/email_notification_policy.json
```

#### How to Enable or Disable Any Email Category Later (Without Restarting Wazuh):
Because `/var/ossec/integrations/custom-html-email.py` reads `/var/ossec/etc/email_notification_policy.json` dynamically on every alert, you can toggle any category on or off immediately without restarting `wazuh-manager`:

```bash
# Example 1: Enable emails for SSH Suspicious Logins (Multi-IP, Root login, Login after brute-force)
sudo /var/ossec/framework/python/bin/python3 -c '
import json
p = "/var/ossec/etc/email_notification_policy.json"
data = json.load(open(p))
data["categories"]["ssh_suspicious_login"] = True
json.dump(data, open(p, "w"), indent=2)
'

# Example 2: Enable emails for Linux User Creation/Deletion
sudo /var/ossec/framework/python/bin/python3 -c '
import json
p = "/var/ossec/etc/email_notification_policy.json"
data = json.load(open(p))
data["categories"]["linux_user_creation_deletion"] = True
json.dump(data, open(p, "w"), indent=2)
'

# Example 3: Disable emails for SFTP Connection Attempts (Default: False)
sudo /var/ossec/framework/python/bin/python3 -c '
import json
p = "/var/ossec/etc/email_notification_policy.json"
data = json.load(open(p))
data["categories"]["sftp_connection_attempts"] = False
json.dump(data, open(p, "w"), indent=2)
'
```

---

### Step 11: Deploy the Redesigned 6-Section HTML Email Integration (`/var/ossec/integrations/custom-html-email.py`)
* **Server:** Wazuh Manager (`wazuh-server` — `172.31.12.109`, RHEL 9.8)
* **File Modified:** `/var/ossec/integrations/custom-html-email.py`

#### Key Capabilities of This Upgraded Integration Script:
1. **Automatic PID Session Cache (`/var/ossec/tmp/sftp_session_cache.json`):** Whenever any user (`ec2-user`, `newuser1`, `eng-001`, etc.) opens an SSH/SFTP session (`Rule 5715` or `100501`), the script caches `(agent_id, pid) -> {username, srcip}` and also caches the most recent file opened by that PID. When subsequent `open`, `close`, `remove`, or `sent status Permission denied` lines arrive for that same `sshd[PID]`, the script automatically populates the **Username**, **Source IP**, **File Name**, and **Full File Path**!
2. **Deduplication Guard:** Prevents duplicate `[MEDIUM]` emails on failed attempts #6, #7, #8, and #9 after attempt #5 has already sent the Medium alert, while allowing attempt #10 (`Rule 100611`/`100612`) to send the `[HIGH] SSH Brute-Force Attack Detected` email immediately.
3. **Standardized 6-Section Executive Layout:**
   * **Header:** `Security Incident Notification • MEDIUM/HIGH Severity` + Clear Incident Name below header.
   * **Section 1:** Incident Summary (Plain English)
   * **Section 2:** Affected Server (Hostname, Server IP, Agent Name, Agent ID, OS)
   * **Section 3:** User Information (Username, UID if available, Group if available, Access Method: `SSH` / `SFTP` / `VNC`, Authentication Status)
   * **Section 4:** Activity Details (Tailored specifically for SSH events vs. SFTP events; only displays fields present in the event—never invents missing values)
   * **Section 5:** Security Explanation
   * **Section 6:** Recommended Actions (No raw JSON dumps or technical clutter)

#### Commands:
```bash
# 1. Back up existing integration script (if present) and extract your existing sender/recipient emails
if [ -f /var/ossec/integrations/custom-html-email.py ]; then
  sudo cp /var/ossec/integrations/custom-html-email.py /var/ossec/integrations/custom-html-email.py.bak
fi

EXISTING_FROM=$(sudo sed -n 's/.*<email_from>\(.*\)<\/email_from>.*/\1/p' /var/ossec/etc/ossec.conf | head -n 1)
EXISTING_TO=$(sudo sed -n 's/.*<email_to>\(.*\)<\/email_to>.*/\1/p' /var/ossec/etc/ossec.conf | head -n 1)
[ -z "$EXISTING_FROM" ] && EXISTING_FROM="<SENDER_EMAIL_ADDRESS>"
[ -z "$EXISTING_TO" ] && EXISTING_TO="<RECIPIENT_EMAIL_ADDRESS>"

# 2. Write the upgraded custom-html-email.py script
sudo tee /var/ossec/integrations/custom-html-email.py << 'EOF'
#!/var/ossec/framework/python/bin/python3
# -*- coding: utf-8 -*-
"""
Wazuh v4.14.9 Configurable HTML Security Incident Notification Engine
- Enforces centralized category policy (/var/ossec/etc/email_notification_policy.json)
- Correlates SFTP PID sessions so all Linux/VNC users resolve Username, Source IP & File Path
- Implements 5-attempt [MEDIUM] and 10-attempt [HIGH] brute-force deduplication
- Renders a clean, 6-section executive HTML + Plain-Text email without raw JSON dumps
"""

import os
import re
import sys
import json
import time
import html
import smtplib
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

SMTP_SERVER = "127.0.0.1"
SMTP_PORT = 25
SENDER_EMAIL = "__SENDER_EMAIL__"
RECIPIENT_EMAILS = ["__RECIPIENT_EMAIL__"]

POLICY_FILE = "/var/ossec/etc/email_notification_policy.json"
CACHE_FILE = "/var/ossec/tmp/sftp_session_cache.json"


def load_json_file(path, default_val):
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return default_val


def save_json_file(path, data):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp_path = f"{path}.tmp.{os.getpid()}"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data, f)
        os.replace(tmp_path, path)
    except Exception:
        pass


def extract_pid(full_log):
    m = re.search(r"(?:sshd|sftp-server|internal-sftp)\[(\d+)\]:", full_log)
    return m.group(1) if m else None


def format_timestamp(ts_str):
    if not ts_str:
        return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    try:
        clean = ts_str.split(".")[0].replace("T", " ")
        return f"{clean} UTC" if not clean.endswith("UTC") else clean
    except Exception:
        return ts_str


def determine_policy_category(rule_id, groups):
    rid = str(rule_id)
    if "notify_sftp_transfer" in groups or rid in ("100502", "100503", "100504", "100507"):
        return "sftp_successful_transfers"
    if "notify_sftp_denied" in groups or rid in ("100505", "100508"):
        return "sftp_failed_denied_operations"
    if "notify_ssh_bruteforce" in groups or rid in ("100601", "100602", "100611", "100612"):
        return "ssh_bruteforce_detection"
    if "notify_sftp_connect" in groups or rid in ("100501", "100511"):
        return "sftp_connection_attempts"
    if "notify_ssh_suspicious" in groups or rid in ("100603", "100604", "100605", "100606", "100607", "100608", "100609", "100610"):
        return "ssh_suspicious_login"
    if "notify_user_mgmt" in groups or rid in ("5902", "5903", "5904", "100630"):
        return "linux_user_creation_deletion"
    if "notify_group_mgmt" in groups or rid in ("5901", "100631"):
        return "linux_group_changes"
    if "notify_vnc" in groups or rid in ("100506", "100509", "100510"):
        return "vnc_session_events"
    if "syscheck" in groups:
        return "file_integrity_monitoring"
    if rid in ("5715", "5716", "5710", "5501", "5502", "5503"):
        return "ssh_authentication_events"
    return "other_security_alerts"


def update_and_resolve_session_context(alert, full_log, agent_id, srcip, dstuser, file_path):
    """
    Correlates OpenSSH / internal-sftp PID across session open, file open, file close, and error lines
    so newly created Linux users always resolve Username, Source IP, and File Path.
    """
    now = int(time.time())
    cache = load_json_file(CACHE_FILE, {"sessions": {}, "dedup": {}})
    sessions = cache.get("sessions", {})

    # Prune cache entries older than 2 hours
    sessions = {k: v for k, v in sessions.items() if now - v.get("ts", 0) < 7200}

    pid = extract_pid(full_log)
    session_key = f"{agent_id}:{pid}" if pid else None

    # Extract username from /home/<username>/... if not already decoded
    if not dstuser and file_path and file_path.startswith("/home/"):
        parts = file_path.split("/")
        if len(parts) >= 3 and parts[2]:
            dstuser = parts[2]

    # Also check raw log patterns if decoder missed username or IP
    if not dstuser:
        m_user = re.search(r"(?:for local user |for invalid user |for )([a-zA-Z0-9_.-]+)", full_log)
        if m_user:
            dstuser = m_user.group(1)
    if not srcip:
        m_ip = re.search(r"from \[?([0-9a-fA-F:.]+)\]?", full_log)
        if m_ip:
            srcip = m_ip.group(1)

    if session_key:
        entry = sessions.get(session_key, {"ts": now})
        entry["ts"] = now
        if dstuser:
            entry["user"] = dstuser
        else:
            dstuser = entry.get("user")

        if srcip:
            entry["srcip"] = srcip
        else:
            srcip = entry.get("srcip")

        if file_path:
            entry["file"] = file_path
        else:
            file_path = entry.get("file")

        sessions[session_key] = entry

    # Fallback: if child sftp-server forked a new PID, match most recent active session for the same user
    if dstuser and not srcip:
        for k, v in sorted(sessions.items(), key=lambda x: x[1].get("ts", 0), reverse=True):
            if k.startswith(f"{agent_id}:") and v.get("user") == dstuser and v.get("srcip"):
                srcip = v.get("srcip")
                break

    cache["sessions"] = sessions
    save_json_file(CACHE_FILE, cache)
    return srcip, dstuser, file_path, cache


def check_and_record_dedup(cache, dedup_key, window_seconds):
    now = int(time.time())
    dedup = cache.get("dedup", {})
    dedup = {k: v for k, v in dedup.items() if now - v < 3600}
    last_sent = dedup.get(dedup_key, 0)
    if now - last_sent < window_seconds:
        return True
    dedup[dedup_key] = now
    cache["dedup"] = dedup
    save_json_file(CACHE_FILE, cache)
    return False


def build_incident_content(rule_id, rule_level, groups, srcip, dstuser, file_path, extra_data, status_val, full_log):
    rid = str(rule_id)
    user_disp = dstuser or "Unknown User"
    ip_disp = srcip or "Unknown IP"
    file_name = os.path.basename(file_path) if file_path else None

    # Default values
    access_method = "SSH"
    auth_status = "Authenticated"
    operation = None
    transfer_result = None
    failed_attempts = None
    user_group = None

    if rid in ("100601", "100602"):
        severity = "MEDIUM"
        incident_name = "SSH Brute-Force Activity Detected"
        access_method = "SSH"
        auth_status = "Failed (5 Unsuccessful Attempts)"
        failed_attempts = "5 failed attempts within 5 minutes"
        summary = (
            f"Five unsuccessful SSH login attempts were detected targeting account '{user_disp}' "
            f"from source IP {ip_disp} within a 5-minute window."
        )
        explanation = (
            "Five unsuccessful SSH login attempts were detected from the same source IP or against the "
            "same username within five minutes. This activity may indicate an automated attempt or "
            "repeated password guessing to gain unauthorized access."
        )
        actions = [
            f"Verify whether the user ('{user_disp}') is authorized and simply mistyped their password.",
            f"Review the source IP address ({ip_disp}) to confirm if it belongs to a known workstation.",
            "Check whether any successful login followed the failed attempts.",
            "Contact the system administrator if the activity is suspicious."
        ]

    elif rid in ("100611", "100612"):
        severity = "HIGH"
        incident_name = "SSH Brute-Force Attack Detected"
        access_method = "SSH"
        auth_status = "Failed (10 Unsuccessful Attempts)"
        failed_attempts = "10 failed attempts within 5 minutes"
        summary = (
            f"An active SSH brute-force attack (10 failed login attempts within 5 minutes) was detected "
            f"from source IP {ip_disp} targeting user '{user_disp}'."
        )
        explanation = (
            "Ten unsuccessful SSH authentication attempts were recorded within five minutes after the "
            "initial medium-severity threshold was exceeded. This strongly indicates a sustained "
            "brute-force attack against the server."
        )
        actions = [
            f"Immediately verify whether source IP {ip_disp} is an unauthorized host.",
            f"Confirm the account status of '{user_disp}' and ensure strong password/key policies are enforced.",
            "Check whether any successful login followed the failed attempts.",
            f"Block source IP {ip_disp} at the firewall or AWS Security Group if unauthorized."
        ]

    elif rid == "100502":
        severity = "MEDIUM"
        incident_name = "SFTP File Transfer Detected"
        access_method = "SFTP"
        auth_status = "Authenticated"
        operation = "Upload (Write / Create)"
        transfer_result = "Upload Initiated / In Progress"
        summary = (
            f"User '{user_disp}' initiated an SFTP file upload ('{file_name or 'file'}') to the "
            "monitored server. The activity was recorded for security auditing."
        )
        explanation = (
            "An authenticated SFTP user opened a file on the server with write/create permissions to "
            "upload data. All SFTP file movements are monitored to protect sensitive engineering assets."
        )
        actions = [
            f"Verify whether user '{user_disp}' is authorized to upload '{file_name or file_path}'.",
            f"Review the source IP address ({ip_disp}) associated with the SFTP session.",
            "Confirm that the uploaded file complies with company data handling policies.",
            "Contact the system administrator if the file upload was unexpected."
        ]

    elif rid == "100503":
        severity = "MEDIUM"
        incident_name = "SFTP File Transfer Detected"
        access_method = "SFTP"
        auth_status = "Authenticated"
        operation = "Download (Read)"
        transfer_result = "Success (File Read)"
        summary = (
            f"User '{user_disp}' downloaded or read a file ('{file_name or 'file'}') from the "
            "monitored server through SFTP. The activity was recorded for security auditing."
        )
        explanation = (
            "An authenticated SFTP user accessed a file for reading/downloading over SFTP. File downloads "
            "are tracked to maintain visibility over intellectual property and server data."
        )
        actions = [
            f"Verify whether user '{user_disp}' is authorized to download '{file_name or file_path}'.",
            f"Review the source IP address ({ip_disp}) used for the SFTP transfer.",
            "Contact the system administrator if the file download is suspicious."
        ]

    elif rid == "100507":
        severity = "MEDIUM"
        incident_name = "SFTP File Transfer Completed"
        access_method = "SFTP"
        auth_status = "Authenticated"
        written = int(extra_data) if str(extra_data).isdigit() else 0
        read_b = int(status_val) if str(status_val).isdigit() else 0
        if written > 0:
            operation = f"Upload Completed ({written} bytes written)"
        else:
            operation = f"Download Completed ({read_b} bytes read)"
        transfer_result = "Completed Successfully"
        summary = (
            f"User '{user_disp}' completed an SFTP file transfer for '{file_name or 'file'}' "
            f"({operation}). The activity was recorded for security auditing."
        )
        explanation = (
            "The SFTP subsystem confirmed that the file handle was closed after transferring data bytes "
            "between the client and the server."
        )
        actions = [
            f"Verify whether user '{user_disp}' was expected to transfer '{file_name or file_path}'.",
            f"Confirm that source IP {ip_disp} is an authorized engineering workstation.",
            "Contact the system administrator if this transfer was unauthorized."
        ]

    elif rid == "100504":
        severity = "MEDIUM"
        incident_name = "SFTP File Modification or Deletion Detected"
        access_method = "SFTP"
        auth_status = "Authenticated"
        if "remove " in full_log or "rmdir " in full_log:
            operation = "Delete"
        elif "rename " in full_log:
            operation = "Rename"
        else:
            operation = "Modify Permissions / Attributes"
        transfer_result = "Completed"
        summary = (
            f"User '{user_disp}' performed an SFTP {operation.lower()} operation on "
            f"'{file_name or file_path}'."
        )
        explanation = (
            "An SFTP user deleted, renamed, or modified attributes of a file on the monitored server."
        )
        actions = [
            f"Verify whether user '{user_disp}' was authorized to {operation.lower()} '{file_name or file_path}'.",
            "Check backups if an important project file was deleted unintentionally.",
            "Contact the system administrator if the activity is suspicious."
        ]

    elif rid == "100505":
        severity = "HIGH"
        incident_name = "SFTP Access Denied"
        access_method = "SFTP"
        auth_status = "Denied (Restricted User Group)"
        user_group = "sftp-denied"
        operation = "SFTP Connection Attempt"
        transfer_result = "Denied / Blocked by Server Policy"
        summary = (
            f"User '{user_disp}' attempted to connect via SFTP from {ip_disp}, but access was "
            "automatically blocked because the account is restricted from using SFTP."
        )
        explanation = (
            "This user account belongs to the restricted 'sftp-denied' group (such as VNC-only users "
            "who are prohibited from transferring files). The SSH daemon intercepted and terminated the "
            "SFTP session before any files could be accessed."
        )
        actions = [
            f"Verify why user '{user_disp}' attempted to initiate an SFTP session from {ip_disp}.",
            "Remind the user of company policy regarding SFTP file transfer restrictions.",
            "If the user legitimately requires SFTP access, obtain management approval before moving them to 'sftp-allowed'.",
            "Investigate recent commands run by this user in their VNC or Linux session."
        ]

    elif rid == "100508":
        severity = "HIGH"
        incident_name = "SFTP File Transfer Failed or Denied"
        access_method = "SFTP"
        auth_status = "Authenticated"
        operation = "File Transfer / Access Attempt"
        transfer_result = "Failed (Permission Denied / Error)"
        summary = (
            f"An SFTP file operation attempted by user '{user_disp}' failed or was denied by the "
            "server filesystem permissions."
        )
        explanation = (
            "The SFTP server rejected a file upload, download, or modification request because the "
            "user lacked filesystem permissions for the target path."
        )
        actions = [
            f"Verify whether user '{user_disp}' attempted to access or overwrite restricted system files.",
            f"Review the source IP ({ip_disp}) and target path ({file_path or 'see server logs'}).",
            "Contact the system administrator if unauthorized privilege probing is suspected."
        ]

    else:
        severity = "HIGH" if rule_level >= 11 else "MEDIUM"
        incident_name = "Security Activity Detected"
        if "sftp" in groups or "notify_sftp_connect" in groups:
            access_method = "SFTP"
        elif "vnc_monitoring" in groups:
            access_method = "VNC"
        summary = f"Wazuh recorded a security event on the monitored server involving user '{user_disp}'."
        explanation = "This activity matched a configured security monitoring rule and was logged for review."
        actions = [
            "Verify whether the user and source IP address are authorized.",
            "Contact the system administrator if the activity is unexpected."
        ]

    return {
        "severity": severity,
        "incident_name": incident_name,
        "summary": summary,
        "access_method": access_method,
        "auth_status": auth_status,
        "user_group": user_group,
        "operation": operation,
        "transfer_result": transfer_result,
        "failed_attempts": failed_attempts,
        "explanation": explanation,
        "actions": actions,
    }


def render_table_rows(rows):
    """Renders only rows whose value is present (never invents missing fields)."""
    out = []
    for label, val, highlight in rows:
        if val is None or str(val).strip() == "" or str(val).strip() == "N/A":
            continue
        safe_val = html.escape(str(val))
        if highlight == "red":
            val_html = f"<span style='color:#b91c1c;font-weight:700;'>{safe_val}</span>"
        elif highlight == "code":
            val_html = f"<code style='background-color:#f3f4f6;padding:2px 6px;border-radius:4px;font-family:monospace;font-size:13px;color:#111827;font-weight:600;'>{safe_val}</code>"
        elif highlight == "bold":
            val_html = f"<strong style='color:#111827;'>{safe_val}</strong>"
        else:
            val_html = safe_val

        out.append(
            f"<tr>"
            f"<td width='36%' style='padding:7px 10px;font-weight:600;color:#4b5563;border-bottom:1px solid #f3f4f6;vertical-align:top;'>{html.escape(label)}</td>"
            f"<td style='padding:7px 10px;color:#1f2937;border-bottom:1px solid #f3f4f6;vertical-align:top;'>{val_html}</td>"
            f"</tr>"
        )
    return "".join(out)


def render_text_rows(rows):
    out = []
    for label, val, _ in rows:
        if val is None or str(val).strip() == "" or str(val).strip() == "N/A":
            continue
        out.append(f"- {label}: {val}")
    return "\n".join(out)


def main():
    if len(sys.argv) < 2:
        sys.exit(0)

    alert_file_path = sys.argv[1]
    try:
        with open(alert_file_path, "r", encoding="utf-8") as f:
            alert = json.load(f)
    except Exception:
        sys.exit(1)

    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    data = alert.get("data", {})
    syscheck = alert.get("syscheck", {})

    rule_id = str(rule.get("id", ""))
    rule_level = int(rule.get("level", 0))
    groups = rule.get("groups", [])
    full_log = alert.get("full_log", "")

    agent_name = agent.get("name", "wazuh-server")
    agent_id = agent.get("id", "000")
    agent_ip = agent.get("ip", "127.0.0.1")

    srcip = data.get("srcip") or data.get("audit", {}).get("srcip")
    srcport = data.get("srcport")
    dstuser = (
        data.get("dstuser")
        or data.get("srcuser")
        or syscheck.get("audit", {}).get("user", {}).get("name")
    )
    uid_val = data.get("uid") or data.get("audit", {}).get("uid") or data.get("audit", {}).get("auid")
    file_path = data.get("file") or syscheck.get("path")
    extra_data = data.get("extra_data")
    status_val = data.get("status")

    # Always update session cache first (even if this specific event category does not send an email!)
    srcip, dstuser, file_path, cache = update_and_resolve_session_context(
        alert, full_log, agent_id, srcip, dstuser, file_path
    )

    # Check centralized email notification policy
    default_policy = {
        "categories": {
            "sftp_successful_transfers": True,
            "sftp_failed_denied_operations": True,
            "ssh_bruteforce_detection": True,
            "sftp_connection_attempts": False,
            "ssh_authentication_events": False,
            "ssh_suspicious_login": False,
            "linux_user_creation_deletion": False,
            "linux_group_changes": False,
            "vnc_session_events": False,
            "file_integrity_monitoring": False,
            "other_security_alerts": False,
        },
        "deduplication_window_seconds": 290,
    }
    policy = load_json_file(POLICY_FILE, default_policy)
    categories = policy.get("categories", default_policy["categories"])
    dedup_window = int(policy.get("deduplication_window_seconds", 290))

    category_key = determine_policy_category(rule_id, groups)
    if not categories.get(category_key, False):
        sys.exit(0)

    # Deduplicate 5-attempt Medium brute-force alerts so attempts #6-#9 do not re-send Medium emails
    if rule_id in ("100601", "100602", "100611", "100612"):
        tier = "HIGH" if rule_id in ("100611", "100612") else "MEDIUM"
        dedup_key = f"bf:{agent_id}:{tier}:{srcip or 'any'}:{dstuser or 'any'}"
        if check_and_record_dedup(cache, dedup_key, dedup_window):
            sys.exit(0)

    info = build_incident_content(
        rule_id, rule_level, groups, srcip, dstuser, file_path, extra_data, status_val, full_log
    )

    severity = info["severity"]
    incident_name = info["incident_name"]
    badge_color = "#b91c1c" if severity == "HIGH" else "#d97706"
    bg_tint = "#fef2f2" if severity == "HIGH" else "#fffbeb"

    timestamp_fmt = format_timestamp(alert.get("timestamp"))
    file_name = os.path.basename(file_path) if file_path else None

    subject = f"[{severity}] {incident_name} | {agent_name}"

    # Section 2 Rows: Affected Server
    server_rows = [
        ("Server Hostname", agent_name, "bold"),
        ("Server IP Address", agent_ip, "code"),
        ("Wazuh Agent Name", agent_name, None),
        ("Wazuh Agent ID", agent_id, None),
        ("Operating System", "Red Hat Enterprise Linux 9.8", None),
    ]

    # Section 3 Rows: User Information
    user_rows = [
        ("Username", dstuser, "bold"),
        ("User ID (UID)", uid_val, None),
        ("User Group", info["user_group"], None),
        ("Access Method", info["access_method"], "bold"),
        ("Authentication Status", info["auth_status"], "red" if "Failed" in info["auth_status"] or "Denied" in info["auth_status"] else "bold"),
    ]

    # Section 4 Rows: Activity Details (SSH vs SFTP specific fields, only shown when available)
    if info["access_method"] == "SFTP":
        activity_rows = [
            ("Source IP", srcip, "red"),
            ("Username", dstuser, "bold"),
            ("File Name", file_name, "code"),
            ("Full File Path", file_path, "code"),
            ("Operation", info["operation"], "bold"),
            ("Transfer Result", info["transfer_result"], "red" if info["transfer_result"] and ("Denied" in info["transfer_result"] or "Failed" in info["transfer_result"]) else "bold"),
            ("Event Timestamp", timestamp_fmt, None),
        ]
    else:
        dest_port = "22 (SSH)" if info["access_method"] == "SSH" else None
        activity_rows = [
            ("Source IP", srcip, "red"),
            ("Destination Server", f"{agent_name} ({agent_ip})", "bold"),
            ("Destination Port", dest_port, None),
            ("Source Port", srcport, None),
            ("Number of Failed Attempts", info["failed_attempts"], "red"),
            ("Authentication Result", info["auth_status"], "red" if "Failed" in info["auth_status"] else "bold"),
            ("Event Timestamp", timestamp_fmt, None),
        ]

    actions_html = "".join(
        f"<li style='margin-bottom:8px;'>{html.escape(a)}</li>" for a in info["actions"]
    )
    actions_text = "\n".join(
        f"{idx+1}. {a}" for idx, a in enumerate(info["actions"])
    )

    plain_text_body = f"""Security Incident Notification • {severity} Severity
{incident_name}
========================================================================

Section 1: Incident Summary
{info['summary']}

Section 2: Affected Server
{render_text_rows(server_rows)}

Section 3: User Information
{render_text_rows(user_rows)}

Section 4: Activity Details
{render_text_rows(activity_rows)}

Section 5: Security Explanation
{info['explanation']}

Section 6: Recommended Actions
{actions_text}
========================================================================
"""

    html_body = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin:0;padding:24px 12px;background-color:#f3f4f6;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#1f2937;">
  <table width="100%" cellpadding="0" cellspacing="0" style="max-width:680px;margin:0 auto;background-color:#ffffff;border:1px solid #e5e7eb;border-radius:10px;overflow:hidden;box-shadow:0 2px 6px rgba(0,0,0,0.05);">
    <tr>
      <td style="background-color:{badge_color};color:#ffffff;padding:20px 26px;">
        <div style="font-size:13px;font-weight:700;letter-spacing:0.6px;text-transform:uppercase;opacity:0.95;">
          Security Incident Notification &bull; {html.escape(severity)} Severity
        </div>
        <div style="font-size:22px;font-weight:700;margin-top:6px;line-height:1.3;">
          {html.escape(incident_name)}
        </div>
      </td>
    </tr>

    <tr>
      <td style="padding:26px;">
        <!-- Section 1: Incident Summary -->
        <h3 style="margin:0 0 10px 0;font-size:15px;color:#111827;border-bottom:2px solid #e5e7eb;padding-bottom:6px;">
          Section 1: Incident Summary
        </h3>
        <p style="margin:0 0 22px 0;font-size:15px;line-height:1.6;color:#1f2937;">
          {html.escape(info['summary'])}
        </p>

        <!-- Section 2: Affected Server -->
        <h3 style="margin:0 0 10px 0;font-size:15px;color:#111827;border-bottom:2px solid #e5e7eb;padding-bottom:6px;">
          Section 2: Affected Server
        </h3>
        <table width="100%" cellpadding="0" cellspacing="0" style="font-size:14px;margin-bottom:22px;">
          {render_table_rows(server_rows)}
        </table>

        <!-- Section 3: User Information -->
        <h3 style="margin:0 0 10px 0;font-size:15px;color:#111827;border-bottom:2px solid #e5e7eb;padding-bottom:6px;">
          Section 3: User Information
        </h3>
        <table width="100%" cellpadding="0" cellspacing="0" style="font-size:14px;margin-bottom:22px;">
          {render_table_rows(user_rows)}
        </table>

        <!-- Section 4: Activity Details -->
        <h3 style="margin:0 0 10px 0;font-size:15px;color:#111827;border-bottom:2px solid #e5e7eb;padding-bottom:6px;">
          Section 4: Activity Details
        </h3>
        <table width="100%" cellpadding="0" cellspacing="0" style="font-size:14px;margin-bottom:22px;background-color:#f9fafb;border:1px solid #e5e7eb;border-radius:6px;">
          {render_table_rows(activity_rows)}
        </table>

        <!-- Section 5: Security Explanation -->
        <h3 style="margin:0 0 10px 0;font-size:15px;color:#111827;border-bottom:2px solid #e5e7eb;padding-bottom:6px;">
          Section 5: Security Explanation
        </h3>
        <div style="background-color:{bg_tint};border-left:4px solid {badge_color};padding:14px 16px;font-size:14px;line-height:1.6;color:#1f2937;margin-bottom:22px;border-radius:0 6px 6px 0;">
          {html.escape(info['explanation'])}
        </div>

        <!-- Section 6: Recommended Actions -->
        <h3 style="margin:0 0 10px 0;font-size:15px;color:#111827;border-bottom:2px solid #e5e7eb;padding-bottom:6px;">
          Section 6: Recommended Actions
        </h3>
        <ol style="margin:0;padding-left:20px;font-size:14px;line-height:1.6;color:#1f2937;">
          {actions_html}
        </ol>
      </td>
    </tr>
  </table>
</body>
</html>
"""

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = SENDER_EMAIL
    msg["To"] = ", ".join(RECIPIENT_EMAILS)

    msg.attach(MIMEText(plain_text_body, "plain", "utf-8"))
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=10) as server:
        server.sendmail(SENDER_EMAIL, RECIPIENT_EMAILS, msg.as_string())


if __name__ == "__main__":
    main()
EOF

# 3. Substitute your actual sender and recipient email addresses from ossec.conf
sudo sed -i "s|__SENDER_EMAIL__|${EXISTING_FROM}|g" /var/ossec/integrations/custom-html-email.py
sudo sed -i "s|__RECIPIENT_EMAIL__|${EXISTING_TO}|g" /var/ossec/integrations/custom-html-email.py

# 4. Set required Wazuh integration ownership and permissions
sudo chown root:wazuh /var/ossec/integrations/custom-html-email.py
sudo chmod 750 /var/ossec/integrations/custom-html-email.py
sudo mkdir -p /var/ossec/tmp
sudo chown root:wazuh /var/ossec/tmp
sudo chmod 770 /var/ossec/tmp
```

#### Validation:
```bash
sudo /var/ossec/framework/python/bin/python3 -m py_compile /var/ossec/integrations/custom-html-email.py
sudo grep -E "SENDER_EMAIL =|RECIPIENT_EMAILS =" /var/ossec/integrations/custom-html-email.py
```

#### Expected Result:
`py_compile` completes with zero syntax errors, and `grep` shows your configured sender and recipient email addresses.

---

### Step 12: Update Wazuh Manager `/var/ossec/etc/ossec.conf` Integration Hook & Restart `wazuh-manager`
* **Server:** Wazuh Manager (`wazuh-server` — `172.31.12.109`, RHEL 9.8)
* **File Modified:** `/var/ossec/etc/ossec.conf`

#### Why We Include `authentication_success` in the Integration Group:
By passing `authentication_success,notify_sftp_connect,notify_sftp_transfer,notify_sftp_denied,notify_ssh_bruteforce,notify_ssh_suspicious,notify_user_mgmt,notify_group_mgmt,notify_vnc,notify_other` to `custom-html-email.py`, the script silently records every new SSH/SFTP user login PID into `/var/ossec/tmp/sftp_session_cache.json` (and exits without emailing if `ssh_authentication_events` and `sftp_connection_attempts` are `false`), guaranteeing that subsequent file upload/download/denied events know the exact username and source IP!

#### Commands:
```bash
# 1. Back up Manager ossec.conf
sudo cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak

# 2. Ensure legacy plain-text wazuh-maild is disabled (<email_notification>no</email_notification>) and remove old <email_alerts> blocks
sudo sed -i 's|<email_notification>yes</email_notification>|<email_notification>no</email_notification>|g' /var/ossec/etc/ossec.conf
sudo sed -i '/<email_alerts>/,/<\/email_alerts>/d' /var/ossec/etc/ossec.conf
sudo sed -i '/<integration>/,/<\/integration>/d' /var/ossec/etc/ossec.conf

# 3. Insert the centralized custom-html-email.py integration block before the first </ossec_config>
sudo sed -i '0,/<\/ossec_config>/s|<\/ossec_config>|  <integration>\n    <name>custom-html-email.py</name>\n    <group>authentication_success,notify_sftp_connect,notify_sftp_transfer,notify_sftp_denied,notify_ssh_bruteforce,notify_ssh_suspicious,notify_user_mgmt,notify_group_mgmt,notify_vnc,notify_other,</group>\n    <alert_format>json</alert_format>\n  </integration>\n\n</ossec_config>|' /var/ossec/etc/ossec.conf

# 4. Validate configuration and restart wazuh-manager
sudo /var/ossec/bin/wazuh-analysisd -t && sudo systemctl restart wazuh-manager
```

#### Validation:
```bash
sudo systemctl status wazuh-manager --no-pager
ps aux | grep wazuh-integratord
```

#### Expected Result:
`wazuh-manager` is `active (running)` and `wazuh-integratord` is active.

---

## 7. Phase 4: Realistic Manual End-to-End Testing & Validation (13 Test Scenarios)

Perform all tests from an **authorized Linux testing machine (`<TEST_CLIENT_IP_1>`)** against the **Monitored Wazuh Agent (`vnc-server` at `172.31.15.219`)** using real SSH, SFTP, and VNC connections.

### Test 1: SSH Login with an Existing User (`ec2-user`)
* **Command (on Test Machine):**
  ```bash
  ssh ec2-user@172.31.15.219
  # Authenticate normally, then type 'exit'
  ```
* **Expected Result:**
  * **Triggered Rule:** `5715` (Level 3 — `sshd: authentication success.`)
  * **Dashboard Visibility:** Logged in Wazuh Dashboard with `data.dstuser: ec2-user` and `data.srcip`.
  * **Email Action:** **Suppressed** (`ssh_authentication_events: false`). Session PID is cached for SFTP correlation.
* **Verification on Wazuh Manager:**
  ```bash
  sudo grep '"id":"5715"' /var/ossec/logs/alerts/alerts.json | grep "ec2-user" | tail -n 1
  ```

---

### Test 2: Creation of New Linux Users (`newuser1`, `newuser2`) & Automatic SSH Login Monitoring
* **Command (on Monitored Agent `vnc-server`):**
  ```bash
  sudo useradd newuser1
  sudo passwd newuser1
  sudo useradd newuser2
  sudo passwd newuser2
  ```
* **Command (on Test Machine — No Wazuh Config Changes Made):**
  ```bash
  ssh newuser1@172.31.15.219
  # Enter newuser1's password, then type 'exit'
  ```
* **Expected Result:**
  * **User Creation Rules Triggered:** `5902` (`New user added to the system`) and `100630` (`Linux User Account Database Modified`).
  * **SSH Login Rule Triggered:** `5715` (`data.dstuser: newuser1`).
  * **Email Action:** **Suppressed** by default (`linux_user_creation_deletion: false`, `ssh_authentication_events: false`).
* **Verification on Wazuh Manager:**
  ```bash
  sudo grep -E '"id":"5902"|"id":"100630"' /var/ossec/logs/alerts/alerts.json | tail -n 2
  sudo grep '"id":"5715"' /var/ossec/logs/alerts/alerts.json | grep "newuser1" | tail -n 1
  ```

---

### Test 3: Five Incorrect SSH Passwords Within 5 Minutes (Medium Brute-Force — Rule `100601` / `100602`)
* **Command (on Test Machine):**
  ```bash
  ssh -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1 newuser1@172.31.15.219
  # Enter an intentionally wrong password. Repeat this command 5 times total within 5 minutes.
  ```
* **Expected Result:**
  * **Attempts 1–4:** Trigger Rule `5716` (Level 5) — **No email sent**.
  * **Attempt 5:** Triggers **Rule `100601` / `100602` (Level 8)**.
  * **Email Action:** **1 Email Sent** with subject `[MEDIUM] SSH Brute-Force Activity Detected | vnc-server`, showing `newuser1`, source IP, and `5 failed attempts within 5 minutes`.
* **Verification on Wazuh Manager:**
  ```bash
  sudo grep -E '"id":"100601"|"id":"100602"' /var/ossec/logs/alerts/alerts.json | tail -n 2
  sudo tail -n 15 /var/log/maillog
  ```

---

### Test 4: Ten Incorrect SSH Passwords Within 5 Minutes (High Brute-Force — Rule `100611` / `100612`)
* **Command (on Test Machine — Continue from Test 3 with 5 more wrong passwords within the same 5-minute window):**
  ```bash
  ssh -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1 newuser1@172.31.15.219
  # Enter an intentionally wrong password 5 more times (attempts #6 through #10).
  ```
* **Expected Result:**
  * **Attempts 6–9:** Deduplicated — **No duplicate Medium emails sent**.
  * **Attempt 10:** Triggers **Rule `100611` / `100612` (Level 12)**.
  * **Email Action:** **1 Email Sent** with subject `[HIGH] SSH Brute-Force Attack Detected | vnc-server`, showing `newuser1`, source IP, and `10 failed attempts within 5 minutes`.
* **Verification on Wazuh Manager:**
  ```bash
  sudo grep -E '"id":"100611"|"id":"100612"' /var/ossec/logs/alerts/alerts.json | tail -n 2
  sudo tail -n 15 /var/log/maillog
  ```

---

### Test 5: Successful SSH Login After Repeated Failures (Rule `100605`)
* **Command (on Test Machine — Immediately after Test 4):**
  ```bash
  ssh newuser1@172.31.15.219
  # Enter the CORRECT password for newuser1, then type 'exit'
  ```
* **Expected Result:**
  * **Triggered Rule:** **Rule `100605` (Level 14)** — `CRITICAL: Successful SSH login by user newuser1... immediately following an SSH brute-force attack`.
  * **Email Action:** Logged in Dashboard; email sent if `ssh_suspicious_login` is set to `true` in `email_notification_policy.json`.
* **Verification on Wazuh Manager:**
  ```bash
  sudo grep '"id":"100605"' /var/ossec/logs/alerts/alerts.json | tail -n 1
  ```

---

### Test 6: SFTP Connection Using `ec2-user` (Connection Only, No File Transfer)
* **Command (on Test Machine):**
  ```bash
  sftp ec2-user@172.31.15.219
  sftp> ls
  sftp> exit
  ```
* **Expected Result:**
  * **Triggered Rules:** `100501` (SFTP Session Opened) and `100511` (SFTP Session Closed).
  * **Email Action:** **Suppressed** (`sftp_connection_attempts: false`), preventing false "file transferred" emails when a user only connects.
* **Verification on Wazuh Manager:**
  ```bash
  sudo grep '"id":"100501"' /var/ossec/logs/alerts/alerts.json | grep "ec2-user" | tail -n 1
  ```

---

### Test 7: SFTP Connection Using Newly Created Linux User (`newuser1`)
* **Command (on Test Machine):**
  ```bash
  sftp newuser1@172.31.15.219
  # Enter newuser1's password
  sftp> pwd
  sftp> exit
  ```
* **Expected Result:**
  * **Triggered Rules:** `100501` (`data.dstuser: newuser1`, `data.srcip: <TEST_CLIENT_IP_1>`) and `100511`.
  * **Email Action:** **Suppressed** (`sftp_connection_attempts: false`).
* **Verification on Wazuh Manager:**
  ```bash
  sudo grep '"id":"100501"' /var/ossec/logs/alerts/alerts.json | grep "newuser1" | tail -n 1
  ```

---

### Test 8: Successful SFTP File Upload by Newly Created User (`newuser1` — Rules `100502` & `100507`)
* **Command (on Test Machine):**
  ```bash
  echo "Semiconductor GDS layout verification payload" > chip_test_v1.gds
  sftp newuser1@172.31.15.219
  sftp> put chip_test_v1.gds
  sftp> exit
  ```
* **Expected Result:**
  * **Triggered Rules:**
    * `100502` (Level 8 — Upload Attempt: `open "/home/newuser1/chip_test_v1.gds" flags WRITE,CREATE,TRUNCATE`)
    * `100507` (Level 8 — Transfer Completed: `close "/home/newuser1/chip_test_v1.gds" bytes read 0 written 46`)
  * **Email Action:** **Enabled (`sftp_successful_transfers: true`)**. Sends formatted HTML email with subject `[MEDIUM] SFTP File Transfer Detected | vnc-server` and `[MEDIUM] SFTP File Transfer Completed | vnc-server` displaying Username `newuser1`, Source IP, File Name `chip_test_v1.gds`, Full Path `/home/newuser1/chip_test_v1.gds`, and Operation `Upload`.
* **Verification on Wazuh Manager:**
  ```bash
  sudo grep -E '"id":"100502"|"id":"100507"' /var/ossec/logs/alerts/alerts.json | tail -n 2
  sudo tail -n 15 /var/log/maillog
  ```

---

### Test 9: SFTP File Download by Newly Created User (`newuser1` — Rule `100503`)
* **Command (on Test Machine):**
  ```bash
  sftp newuser1@172.31.15.219
  sftp> get chip_test_v1.gds downloaded_chip.gds
  sftp> exit
  ```
* **Expected Result:**
  * **Triggered Rule:** `100503` (Level 8 — `SFTP File Transfer Detected (Download)`) and `100507` (Transfer Completed).
  * **Email Action:** **Enabled**. Sends HTML email `[MEDIUM] SFTP File Transfer Detected | vnc-server` showing `newuser1`, `chip_test_v1.gds`, and `Download (Read)`.
* **Verification on Wazuh Manager:**
  ```bash
  sudo grep '"id":"100503"' /var/ossec/logs/alerts/alerts.json | tail -n 1
  ```

---

### Test 10: SFTP Access Denied for a Restricted User (`newuser2` in `sftp-denied` — Rule `100505`)
* **Command (on Monitored Agent `vnc-server`):**
  ```bash
  sudo usermod -aG sftp-denied newuser2
  ```
* **Command (on Test Machine):**
  ```bash
  sftp newuser2@172.31.15.219
  # Enter newuser2's password -> Connection immediately closes
  ```
* **Expected Result:**
  * **Triggered Rule:** **Rule `100505` (Level 12)** — `SFTP Access Denied: Restricted user newuser2 from IP <TEST_CLIENT_IP_1> attempted SFTP access`.
  * **Email Action:** **Enabled (`sftp_failed_denied_operations: true`)**. Sends HTML email with subject `[HIGH] SFTP Access Denied | vnc-server`, showing Username `newuser2`, User Group `sftp-denied`, Access Method `SFTP`, and Transfer Result `Denied / Blocked by Server Policy`.
* **Verification on Wazuh Manager:**
  ```bash
  sudo grep '"id":"100505"' /var/ossec/logs/alerts/alerts.json | tail -n 1
  sudo tail -n 15 /var/log/maillog
  ```

---

### Test 11: SFTP File Transfer Attempt That Fails Due to Permission Denied (Rule `100508`)
* **Command (on Test Machine using `newuser1`):**
  ```bash
  sftp newuser1@172.31.15.219
  sftp> put chip_test_v1.gds /etc/unauthorized_chip.gds
  # Outputs: remote open("/etc/unauthorized_chip.gds"): Permission denied
  sftp> exit
  ```
* **Expected Result:**
  * **Triggered Rule:** **Rule `100508` (Level 11)** — `SFTP File Operation Failed/Denied: SFTP server returned error status`.
  * **Email Action:** **Enabled (`sftp_failed_denied_operations: true`)**. Sends HTML email with subject `[HIGH] SFTP File Transfer Failed or Denied | vnc-server` showing `newuser1`, source IP, and `Failed (Permission Denied / Error)`.
* **Verification on Wazuh Manager:**
  ```bash
  sudo grep '"id":"100508"' /var/ossec/logs/alerts/alerts.json | tail -n 1
  ```

---

### Test 12: VNC Login Using a VNC-Enabled Linux User (Rules `100509` & `100510`)
* **Command:** Connect to `vnc-server` (`172.31.15.219:5901`) using TigerVNC Viewer with a configured VNC user (first with an incorrect password, then with the correct password).
* **Expected Result:**
  * **Triggered Rules:** `100510` (Level 8 — `VNC Authentication Failed`) and `100509` (Level 5 — `VNC Session Opened`).
  * **Email Action:** Logged in Wazuh Dashboard; email suppressed by default (`vnc_session_events: false`) and configurable via `email_notification_policy.json`.
* **Verification on Wazuh Manager:**
  ```bash
  sudo grep -E '"id":"100509"|"id":"100510"' /var/ossec/logs/alerts/alerts.json | tail -n 2
  ```

---

### Test 13: Cleanup of Test Users After Validation
* **Command (on Monitored Agent `vnc-server`):**
  ```bash
  sudo userdel -r newuser1
  sudo userdel -r newuser2
  ```

---

## 8. Rollback Instructions

If you ever need to revert any change to its pre-audit state, run the following commands on the respective server:

### 8.1 Rollback on Wazuh Agent (`vnc-server`)
```bash
sudo cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
sudo cp /etc/ssh/sshd_config.d/50-sftp-monitoring.conf.bak /etc/ssh/sshd_config.d/50-sftp-monitoring.conf
sudo sshd -t && sudo systemctl reload sshd

sudo cp /etc/audit/rules.d/wazuh-full-monitoring.rules.bak /etc/audit/rules.d/wazuh-full-monitoring.rules
sudo augenrules --load

sudo cp /var/ossec/etc/ossec.conf.bak /var/ossec/etc/ossec.conf
sudo systemctl restart wazuh-agent
```

### 8.2 Rollback on Wazuh Manager (`wazuh-server`)
```bash
sudo cp /var/ossec/etc/decoders/sftp_decoders.xml.bak /var/ossec/etc/decoders/sftp_decoders.xml
sudo cp /var/ossec/etc/rules/sftp_and_vnc_rules.xml.bak /var/ossec/etc/rules/sftp_and_vnc_rules.xml
sudo cp /var/ossec/etc/rules/ssh_and_network_rules.xml.bak /var/ossec/etc/rules/ssh_and_network_rules.xml
sudo cp /var/ossec/integrations/custom-html-email.py.bak /var/ossec/integrations/custom-html-email.py
sudo cp /var/ossec/etc/ossec.conf.bak /var/ossec/etc/ossec.conf

sudo /var/ossec/bin/wazuh-analysisd -t && sudo systemctl restart wazuh-manager
```
