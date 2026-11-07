# Wazuh Complete Monitoring, SSH/SFTP/VNC Auditing, and Team Management Guide (v1.0)

## 1. Architecture and Prerequisites

### 1.1 Environment Topology

This guide documents a two-server monitoring architecture running on **Red Hat Enterprise Linux (RHEL) 9.8 (`x86_64`)** on AWS EC2:

| Component Role | Hostname Placeholder | Private IP Placeholder | Operating System | Key Services |
| :--- | :--- | :--- | :--- | :--- |
| **Wazuh All-in-One Server** | `ec2-user` | `<WAZUH_MANAGER_IP>` | RHEL 9.8 (`x86_64`) | `wazuh-manager`, `wazuh-indexer`, `wazuh-dashboard`, `filebeat`, `postfix` |
| **Monitored VNC/SFTP Server** | `vnc-server` | `<SERVER_PRIVATE_IP>` | RHEL 9.8 (`x86_64`) | `wazuh-agent`, `sshd`, `vncserver@:1..:N`, `auditd`, `rsyslog`, `firewalld` |

### 1.2 Event Pipeline Architecture

```text
[Monitored Server: vnc-server (<SERVER_PRIVATE_IP>)]
  |-- /var/log/secure (SSH, PAM, SFTP session open/close)
  |-- /srv/sftp/<user>/dev/log -> rsyslog -> /var/log/secure (Chrooted SFTP file actions)
  |-- /var/log/audit/audit.log (Kernel execve commands, user/group modifications)
  |-- /home/*/.local/share/tigervnc/*.log & /home/*/.vnc/*.log (TigerVNC display logs)
        |
        v
  [wazuh-agent (TCP 1514 TLS)]
        |
        v
[Wazuh Server: ec2-user (<WAZUH_MANAGER_IP>)]
  |-- wazuh-remoted -> wazuh-analysisd
  |-- Decoders: /var/ossec/etc/decoders/sftp_and_vnc_decoders.xml
  |-- Rules:    /var/ossec/etc/rules/sftp_and_vnc_rules.xml
  |             /var/ossec/etc/rules/ssh_and_network_rules.xml
        |
        +---> /var/ossec/logs/alerts/alerts.json ---> Filebeat ---> Wazuh Dashboard (443/TCP)
        |
        +---> wazuh-integratord ---> /var/ossec/integrations/custom-html-email.py
                                       |-- Reads /var/ossec/etc/email_notification_policy.json
                                       |-- Enforces Incident Deduplication & PID Session Cache
                                       |-- Sends via Local Postfix (127.0.0.1:25) -> Gmail STARTTLS (587)
```

### 1.3 Network Port Requirements

| Source | Destination | Port / Protocol | Purpose |
| :--- | :--- | :--- | :--- |
| `<SERVER_PRIVATE_IP>` | `<WAZUH_MANAGER_IP>` | `1514/TCP` | Wazuh Agent event stream |
| `<SERVER_PRIVATE_IP>` | `<WAZUH_MANAGER_IP>` | `1515/TCP` | Wazuh Agent enrollment |
| Admin Workstation | `<WAZUH_MANAGER_IP>` | `443/TCP` | Wazuh Dashboard HTTPS access |
| `<WAZUH_MANAGER_IP>` | `smtp.gmail.com` | `587/TCP` | Outbound Postfix STARTTLS relay |
| Engineering Clients | `<SERVER_PRIVATE_IP>` | `22/TCP`, `5901-5904/TCP` | SSH/SFTP and TigerVNC access |

---

## 2. Environment Variables and Placeholders

Replace the placeholder values below with your actual environment values before executing commands. Never commit real passwords or SMTP App Passwords into scripts or Git repositories.

```bash
# ============================================================================
# ENVIRONMENT VARIABLES - REPLACE THESE VALUES FOR YOUR ENVIRONMENT
# ============================================================================

# Wazuh Manager Server
WAZUH_MANAGER_IP="172.31.7.137"                        # e.g., 172.31.15.207
WAZUH_MANAGER_HOSTNAME="ec2-user"      # e.g., wazuh-server

# Monitored Linux / VNC / SFTP Agent Server
WAZUH_AGENT_IP="172.31.9.50"             # e.g., 172.31.15.62
WAZUH_AGENT_NAME="vnc-server"                   # e.g., vnc-server
SERVER_HOSTNAME="vnc-server"                    # e.g., vnc-server
SERVER_PRIVATE_IP="<SERVER_PRIVATE_IP>"                # e.g., 172.31.15.62

# Linux & VNC User Placeholders
LINUX_USERNAME="<LINUX_USERNAME>"                      # e.g., user1, user2, user3, user4
LINUX_GROUP="<LINUX_GROUP>"                            # e.g., sftp-allowed or sftp-denied
VNC_DISPLAY="<VNC_DISPLAY_NUMBER>"                     # e.g., :1, :2, :3, :4

# Postfix Gmail SMTP Relay Placeholders
SMTP_HOST="smtp.gmail.com"
SMTP_PORT="587"
SMTP_USERNAME="devops.jakir@gmail.com"                        # Sender Gmail address
SMTP_APP_PASSWORD="<GMAIL_APP_PASSWORD>"               # 16-character Google App Password
ALERT_RECIPIENT_EMAIL="hiddenclue0@gmail.com"        # Destination email address for alerts

# Wazuh Dashboard Team Account Placeholders
WAZUH_ADMIN_USERNAME="admin"          # Full administrative user
WAZUH_ANALYST_USERNAME="jakir"      # Security analyst user
WAZUH_VIEWER_USERNAME="viewuser"        # Read-only auditor/viewer user
```

---

## 3. Existing Wazuh Deployment Discovery

Before changing any files, inspect the current state on both servers.

### 3.1 Inspect Wazuh Manager Version, Services, and Connected Agents

* **Location:** Wazuh Manager (`ec2-user`)
* **Execution user:** `root`
* **Purpose:** Verify the installed Wazuh Manager version, service health, and registered agents.

```bash
/var/ossec/bin/wazuh-control info
systemctl status wazuh-manager wazuh-indexer wazuh-dashboard filebeat --no-pager
/var/ossec/bin/agent_control -l
```

* **Validation:** `wazuh-control info` shows `WAZUH_VERSION="v4.14.9"`, all four services show `active (running)`, and `agent_control -l` lists your monitored agent (`Active`).

### 3.2 Inspect Monitored Agent Installation, Users, SSHD, and VNC State

* **Location:** Wazuh Agent (`vnc-server`)
* **Execution user:** `root`
* **Purpose:** Verify whether `wazuh-agent` is installed, inspect existing Linux users (`ec2-user`, `user1`–`user4`), and check active SSH/SFTP and TigerVNC settings.

```bash
rpm -q wazuh-agent tigervnc-server openssh-server
systemctl status wazuh-agent --no-pager
getent passwd ec2-user user1 user2 user3 user4
getent group sftp-allowed sftp-denied
sshd -T | grep -E "loglevel|syslogfacility|subsystem|denygroups"
ls -la /etc/ssh/sshd_config.d/
```

* **Validation:** Confirms whether `wazuh-agent` is installed and connected, lists UIDs/groups for `ec2-user` and `user1`–`user4`, and displays the active `sshd` configuration.

---

## 4. Backup and Recovery Preparation

Back up all existing configuration files on both servers before applying fixes.

### 4.1 Back Up Wazuh Manager Configuration Files

* **Location:** Wazuh Manager (`ec2-user`)
* **Execution user:** `root`
* **Purpose:** Create a timestamped backup of all Wazuh Manager configs, rules, decoders, integrations, and Postfix files.

```bash
BACKUP_DIR="/root/wazuh_manager_backup_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

cp -a /var/ossec/etc/ossec.conf "$BACKUP_DIR/"
cp -a /var/ossec/etc/decoders "$BACKUP_DIR/"
cp -a /var/ossec/etc/rules "$BACKUP_DIR/"
cp -a /var/ossec/integrations "$BACKUP_DIR/"
[ -f /var/ossec/etc/email_notification_policy.json ] && cp -a /var/ossec/etc/email_notification_policy.json "$BACKUP_DIR/"
[ -d /etc/postfix ] && cp -a /etc/postfix "$BACKUP_DIR/"

ls -la "$BACKUP_DIR"
```

* **Validation:** `ls -la "$BACKUP_DIR"` displays copies of `ossec.conf`, `decoders`, `rules`, `integrations`, and `postfix`.

### 4.2 Back Up Wazuh Agent, SSHD, Auditd, and TigerVNC Configuration Files

* **Location:** Wazuh Agent (`vnc-server`)
* **Execution user:** `root`
* **Purpose:** Create a timestamped backup of all SSHD, Auditd, Rsyslog, TigerVNC, and Wazuh Agent configurations.

```bash
AGENT_BACKUP_DIR="/root/wazuh_agent_backup_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$AGENT_BACKUP_DIR"

cp -a /etc/ssh/sshd_config "$AGENT_BACKUP_DIR/"
cp -a /etc/ssh/sshd_config.d "$AGENT_BACKUP_DIR/"
[ -d /etc/audit/rules.d ] && cp -a /etc/audit/rules.d "$AGENT_BACKUP_DIR/"
[ -d /etc/tigervnc ] && cp -a /etc/tigervnc "$AGENT_BACKUP_DIR/"
[ -f /var/ossec/etc/ossec.conf ] && cp -a /var/ossec/etc/ossec.conf "$AGENT_BACKUP_DIR/"

ls -la "$AGENT_BACKUP_DIR"
```

* **Validation:** `ls -la "$AGENT_BACKUP_DIR"` displays all backed-up directories and files.

---

## 5. Wazuh Manager Configuration

Configure `/var/ossec/etc/ossec.conf` on the Wazuh Manager so that:
1. Built-in `wazuh-maild` (`<email_notification>no</email_notification>`) is disabled to prevent duplicate plain-text emails.
2. Only **one** `<integration>` block exists for `custom-html-email.py` (preventing `wazuh-integratord` from firing twice per alert).

### 5.1 Configure Clean Integration Block in Manager `ossec.conf`

* **Location:** Wazuh Manager (`ec2-user`)
* **Execution user:** `root`
* **Purpose:** Ensure `ossec.conf` disables legacy `wazuh-maild` and registers `custom-html-email.py` once.

```bash
cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.pre_fix

# 1. Disable legacy plain-text wazuh-maild and remove any old <email_alerts> or duplicate <integration> blocks
sed -i 's|<email_notification>yes</email_notification>|<email_notification>no</email_notification>|g' /var/ossec/etc/ossec.conf
sed -i '/<email_alerts>/,/<\/email_alerts>/d' /var/ossec/etc/ossec.conf
sed -i '/<integration>/,/<\/integration>/d' /var/ossec/etc/ossec.conf

# 2. Insert a single clean <integration> block before the first </ossec_config>
sed -i '0,/<\/ossec_config>/s|<\/ossec_config>|  <integration>\n    <name>custom-html-email.py</name>\n    <group>authentication_success,sftp_session,notify_sftp_connect,notify_sftp_transfer,notify_sftp_denied,notify_ssh_bruteforce,notify_ssh_suspicious,notify_user_mgmt,notify_group_mgmt,notify_vnc,notify_fim,notify_other,</group>\n    <alert_format>json</alert_format>\n  </integration>\n\n</ossec_config>|' /var/ossec/etc/ossec.conf

/var/ossec/bin/wazuh-analysisd -t
```

* **Validation:** Run `grep -n -C 5 "custom-html-email.py" /var/ossec/etc/ossec.conf` and verify only one `<integration>` block exists and `wazuh-analysisd -t` returns no errors.

---

## 6. Wazuh Agent Installation and Configuration

Ensure the Wazuh Agent (`v4.14.9`) is installed on `vnc-server`, enrolled with `<WAZUH_MANAGER_IP>`, and configured to collect all required log sources without duplication.

### 6.1 Install or Verify Wazuh Agent v4.14.9

* **Location:** Wazuh Agent (`vnc-server`)
* **Execution user:** `root`
* **Purpose:** Install Wazuh Agent v4.14.9 (if not yet installed) and connect it to `<WAZUH_MANAGER_IP>`.

```bash
WAZUH_MANAGER_IP="172.31.7.137"
WAZUH_AGENT_NAME="vnc-server"

rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH

if ! rpm -q wazuh-agent >/dev/null 2>&1; then
    curl -sO https://packages.wazuh.com/4.x/yum/wazuh-agent-4.14.9-1.x86_64.rpm
    WAZUH_MANAGER="${WAZUH_MANAGER_IP}" WAZUH_AGENT_NAME="${WAZUH_AGENT_NAME}" rpm -Uvh wazuh-agent-4.14.9-1.x86_64.rpm
    rm -f wazuh-agent-4.14.9-1.x86_64.rpm
fi

grep -q "logcollector.loop_timeout" /var/ossec/etc/local_internal_options.conf || \
    echo "logcollector.loop_timeout=1" >> /var/ossec/etc/local_internal_options.conf
```

* **Validation:** `rpm -q wazuh-agent` outputs `wazuh-agent-4.14.9-1.x86_64`.

### 6.2 Configure Agent `/var/ossec/etc/ossec.conf` (Eliminating `journald` + `/var/log/secure` Double Ingestion)

**Critical Root-Cause Fix:** Default Wazuh 4.14 installations on RHEL 9 include `<location>journald</location>` at the bottom of `ossec.conf`. If you also add `<location>/var/log/secure</location>` without removing `journald`, **every single SSH and SFTP log line is sent to the Wazuh Manager twice** (once via `journald` and once via `/var/log/secure`). That causes 3 failed logins to count as 6, and triggers duplicate alerts! The configuration below uses `/var/log/secure`, `/var/log/messages`, `/var/log/audit/audit.log`, and TigerVNC log globs cleanly without `journald` duplication.

* **Location:** Wazuh Agent (`vnc-server`)
* **Execution user:** `root`
* **Purpose:** Configure complete, non-duplicated log collection and real-time Whodata File Integrity Monitoring (FIM).

```bash
WAZUH_MANAGER_IP="172.31.7.137"

cat << EOF > /var/ossec/etc/ossec.conf
<ossec_config>
  <client>
    <server>
      <address>${WAZUH_MANAGER_IP}</address>
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
    <directories check_all="yes" whodata="yes">/boot,/home,/root,/srv/sftp</directories>

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
    <ignore type="sregex">.log$|.swp$|/dev/log$</ignore>

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
    <location>/home/*/.local/share/tigervnc/*.log</location>
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

chown root:wazuh /var/ossec/etc/ossec.conf
chmod 660 /var/ossec/etc/ossec.conf
systemctl enable --now wazuh-agent
systemctl restart wazuh-agent
```

* **Validation:** Run `grep "Connected to the server" /var/ossec/logs/ossec.log | tail -n 2` to verify connection to `<WAZUH_MANAGER_IP>`.

---

## 7. Linux Authentication and Auditd Monitoring

Configure Linux kernel `auditd` rules on `vnc-server` so every command run by any user (`auid >= 1000`), every user/group modification (`useradd`, `usermod`, `userdel`, `passwd`, `gpasswd`), and every SSH/TigerVNC configuration edit is recorded in `/var/log/audit/audit.log`.

### 7.1 Configure Kernel `auditd` Rules for All Users

* **Location:** Wazuh Agent (`vnc-server`)
* **Execution user:** `root`
* **Purpose:** Load comprehensive `auditd` rules for all interactive UIDs ($\ge 1000$) and system identity files.

```bash
rm -f /etc/audit/rules.d/wazuh-command-audit.rules
mkdir -p /etc/tigervnc /etc/firewalld /etc/NetworkManager/system-connections /etc/ssh/sshd_config.d

cat << 'EOF' > /etc/audit/rules.d/wazuh-full-monitoring.rules
-D
-b 8192

## 1. Track all commands executed by any human user (auid >= 1000)
-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=-1 -k audit-wazuh-c
-a always,exit -F arch=b32 -S execve -F auid>=1000 -F auid!=-1 -k audit-wazuh-c

## 2. Track user account and password modifications
-w /etc/passwd -p wa -k user-modify
-w /etc/shadow -p wa -k user-modify
-w /etc/security/opasswd -p wa -k user-modify

## 3. Track group membership modifications
-w /etc/group -p wa -k group-modify
-w /etc/gshadow -p wa -k group-modify

## 4. Track TigerVNC configuration changes
-w /etc/tigervnc/ -p wa -k vnc-config-modify
-w /etc/pam.d/tigervnc -p wa -k vnc-config-modify

## 5. Track SSH/SFTP configuration changes
-w /etc/ssh/sshd_config -p wa -k sshd-config-modify
-w /etc/ssh/sshd_config.d/ -p wa -k sshd-config-modify

## 6. Track Firewall and Network configuration changes
-w /etc/firewalld/ -p wa -k network-config-modify
-w /etc/NetworkManager/system-connections/ -p wa -k network-config-modify
-w /etc/hosts -p wa -k network-config-modify
-w /etc/resolv.conf -p wa -k network-config-modify
EOF

augenrules --load
```

* **Validation:** Run `auditctl -l` and verify all 15 rules are active in the kernel.

---

## 8. SSH Monitoring Configuration

### 8.1 Why SSH Brute-Force Failed for `ec2-user` and `user3` Previously

1. **`ec2-user` Passwordless Rejection:** In your previous test (`ssh ec2-user@172.31.15.62`), `ec2-user` did not have a Linux password set, or the client did not offer password authentication (`Permission denied (publickey,gssapi-keyex,gssapi-with-mic)`). When SSH closes during `[preauth]` without a password prompt, OpenSSH logs `Connection closed by authenticating user ec2-user ... [preauth]` (Rule `5722`, Level 0), **not** `Failed password`.
2. **`user3` (`sftp-denied`) Blocked Before Password Prompt:** In your `/etc/ssh/sshd_config.d/40-sftp-access.conf`, you had `DenyGroups sftp-denied` AND `Match Group sftp-denied` with `PasswordAuthentication no`. Because `PasswordAuthentication no` was set for `sftp-denied`, OpenSSH never prompted `user3` for a password and immediately rejected the connection at `[preauth]`.
3. **Fix:**
   * Keep `LogLevel VERBOSE` and `Subsystem sftp internal-sftp -f AUTHPRIV -l INFO` globally at the top of `/etc/ssh/sshd_config.d/40-sftp-access.conf`.
   * For `Match Group sftp-denied`, use `ForceCommand /usr/sbin/nologin` (instead of `DenyGroups` + `PasswordAuthentication no`) so that:
     * If an attacker brute-forces `user3`'s password, OpenSSH logs `Failed password for user3` and triggers the 5-attempt / 10-attempt SSH Brute-Force alert!
     * If `user3` enters their valid password to attempt SFTP or SSH, OpenSSH logs `Starting session: forced-command (config) '/usr/sbin/nologin' for user3 from <IP>` and immediately disconnects them, triggering **Rule `100505` (`[HIGH] SFTP Access Denied`)** with `user3`'s exact username and source IP!

### 8.2 Configure `/etc/ssh/sshd_config.d/40-sftp-access.conf`

* **Location:** Wazuh Agent (`vnc-server`)
* **Execution user:** `root`
* **Purpose:** Configure global verbose SSH/SFTP logging, chroot SFTP for `sftp-allowed`, and audited denial for `sftp-denied`.

```bash
# 1. Remove any competing drop-in file we created earlier so there is only ONE authoritative file
rm -f /etc/ssh/sshd_config.d/50-sftp-monitoring.conf

# 2. Comment out legacy Subsystem sftp in main /etc/ssh/sshd_config
sed -i 's/^[[:space:]]*Subsystem[[:space:]]\+sftp/#Subsystem sftp/g' /etc/ssh/sshd_config

# 3. Write authoritative /etc/ssh/sshd_config.d/40-sftp-access.conf
cat << 'EOF' > /etc/ssh/sshd_config.d/40-sftp-access.conf
# Global Verbose SSH & SFTP Logging for ALL Users
LogLevel VERBOSE
SyslogFacility AUTHPRIV
PasswordAuthentication yes
KbdInteractiveAuthentication yes
Subsystem sftp internal-sftp -f AUTHPRIV -l INFO -u 0022

# SFTP-Allowed Users (Chrooted to /srv/sftp/%u with verbose file transfer logging)
Match Group sftp-allowed
    PasswordAuthentication yes
    ChrootDirectory /srv/sftp/%u
    ForceCommand internal-sftp -f AUTHPRIV -l INFO -u 0022
    AllowTcpForwarding no
    X11Forwarding no
    PermitTTY no

# SFTP-Denied Users (VNC-only accounts: logs failed passwords AND logs/blocks SFTP/SSH access)
Match Group sftp-denied
    PasswordAuthentication yes
    ForceCommand /usr/sbin/nologin
    AllowTcpForwarding no
    X11Forwarding no
    PermitTTY no
EOF

chmod 600 /etc/ssh/sshd_config.d/40-sftp-access.conf
sshd -t && systemctl reload sshd
```

* **Validation:**
  ```bash
  sshd -T -C user=user1,host=localhost,addr=127.0.0.1 | grep -E '^(loglevel|chrootdirectory|forcecommand|subsystem)'
  sshd -T -C user=user3,host=localhost,addr=127.0.0.1 | grep -E '^(loglevel|chrootdirectory|forcecommand|passwordauthentication)'
  ```

---

## 9. SFTP Monitoring (Fixing Chroot Logging & `ec2-user` Misattribution)

### 9.1 Root Cause of Two Critical SFTP Issues

1. **Why Chrooted SFTP (`user1`, `user2`) Produced Zero File Logs:**
   When `sshd` chroots `user1` into `/srv/sftp/user1`, the `internal-sftp` process can no longer access `/dev/log` on the host filesystem unless a UNIX datagram socket exists at `/srv/sftp/user1/dev/log`. Without it, `session opened`, `open`, `close`, and `remove` logs are silently discarded by libc `syslog()`.
2. **Why an SFTP Action by Another User Was Reported as `ec2-user`:**
   Look at `/var/ossec/etc/ossec.conf` on your agent: `<syscheck>` monitors `/home` and `/srv/sftp` with `whodata="yes"` (Rule `550` / `554`). When an administrator is logged in via SSH as `ec2-user` and runs `sudo su -` to create files or test SFTP locally from the same box, the Linux kernel's Immutable Login UID (`auid`) remains `1000` (`ec2-user`) across `sudo`/`su` transitions! Furthermore, in our previous rule `100502`, `<group>syscheck,sftp_transfer...</group>` included the `syscheck` group, and in `custom-html-email.py`, `syscheck.audit.user.name` (`auid`) was checked when `data.dstuser` was empty on an SFTP `open` line!
   * **Fix:**
     * Configure `rsyslog` with `$AddUnixListenSocket /srv/sftp/<user>/dev/log` (or bind-mount `/run/systemd/journal/dev-log`) so chrooted `internal-sftp` writes real `open` and `close` logs to `/var/log/secure`.
     * Remove `syscheck` from the `<group>` tag of SFTP rules `100502` and `100504`.
     * In `custom-html-email.py`, resolve the SFTP username strictly from the `sshd[PID]` session cache (`session opened for local user <username> from [<srcip>]`) or file path, **never** from an unrelated `auid` (`ec2-user`).

### 9.2 Configure Chroot `/dev/log` Sockets for Existing Users (`user1`, `user2`)

* **Location:** Wazuh Agent (`vnc-server`)
* **Execution user:** `root`
* **Purpose:** Bind-mount `/run/systemd/journal/dev-log` into `/srv/sftp/user1/dev/log` and `/srv/sftp/user2/dev/log` so chrooted `internal-sftp` processes log every file transfer to `/var/log/secure`.

```bash
for u in user1 user2; do
    mkdir -p /srv/sftp/$u/dev /srv/sftp/$u/files
    chown root:root /srv /srv/sftp /srv/sftp/$u /srv/sftp/$u/dev
    chmod 755 /srv /srv/sftp /srv/sftp/$u /srv/sftp/$u/dev
    chown $u:sftp-allowed /srv/sftp/$u/files
    chmod 700 /srv/sftp/$u/files

    touch /srv/sftp/$u/dev/log
    if ! mountpoint -q /srv/sftp/$u/dev/log && ! grep -q "/srv/sftp/$u/dev/log" /proc/mounts; then
        mount --bind /run/systemd/journal/dev-log /srv/sftp/$u/dev/log
    fi
    grep -q "/srv/sftp/$u/dev/log" /etc/fstab || \
        echo "/run/systemd/journal/dev-log /srv/sftp/$u/dev/log none bind 0 0" >> /etc/fstab
done

semanage fcontext -a -t user_home_t "/srv/sftp/[^/]+/files(/.*)?" 2>/dev/null || true
restorecon -Rv /srv/sftp
setsebool -P ssh_chroot_rw_homedirs on
systemctl restart rsyslog
```

* **Validation:** Run `grep "/srv/sftp" /proc/mounts` and confirm both `/srv/sftp/user1/dev/log` and `/srv/sftp/user2/dev/log` are active mounts.

---

## 10. TigerVNC Monitoring (Architecture, Limitations, and Attribution)

### 10.1 How TigerVNC Authenticates in Your Current Configuration

In your setup (`/etc/tigervnc/vncserver-config-defaults`), TigerVNC is configured with:
```ini
session=gnome
geometry=1920x1080
securitytypes=vncauth,tlsvnc
```
And displays are mapped in `/etc/tigervnc/vncserver.users`:
* `:1=user1` (Port `5901`)
* `:2=user2` (Port `5902`)
* `:3=user3` (Port `5903`)
* `:4=user4` (Port `5904`)

### 10.2 Important Technical Limitation & How We Solve User Attribution

1. **Systemd Service Startup (`pam_unix(tigervnc:session)`):** When `systemctl start vncserver@:1.service` starts, `/var/log/secure` logs:
   `pam_unix(tigervnc:session): session opened for user user1(uid=1001) by (uid=0)`
   This identifies the **Linux username (`user1`)** and **UID (`1001`)** when the VNC desktop starts or stops, but does **not** include the remote VNC client's IP address.
2. **VNC Client Network Connection (`Xvnc` Log):** Because `securitytypes=vncauth,tlsvnc` uses each user's `/home/<user>/.config/tigervnc/passwd` (8-byte VNC password) rather than Linux PAM, client connections are logged inside the user's VNC log file:
   `/home/<username>/.local/share/tigervnc/<hostname>:<display>.log` (on RHEL 9 TigerVNC 1.15)
   * Connection accepted: `Connections: accepted: <CLIENT_IP>::<PORT>`
   * Authentication failed: `Connections: closed: <CLIENT_IP>::<PORT> (AuthFailureException: Authentication failure)`
   * Session closed: `Connections: closed: <CLIENT_IP>::<PORT> (Clean disconnection)`
3. **How Wazuh Attributes the Exact Linux Username and Display:**
   Because Wazuh Agent collects `/home/*/.local/share/tigervnc/*.log`, every alert generated from that log file carries the exact file path in the JSON alert metadata (`"location": "/home/user1/.local/share/tigervnc/vnc-server:1.log"`). Our custom decoders extract the **Source IP (`srcip`)** from `Connections: accepted/closed`, and our integration script (`custom-html-email.py`) extracts the **Linux Username (`user1`)** and **VNC Display (`:1`)** directly from the `location` path!

### 10.3 Ensure TigerVNC Log Permissions Allow Wazuh Agent Collection

* **Location:** Wazuh Agent (`vnc-server`)
* **Execution user:** `root`
* **Purpose:** Verify TigerVNC log files exist under `/home/<user>/.local/share/tigervnc/` and restart `wazuh-agent` so wildcard log collection attaches to them.

```bash
ls -la /home/*/.local/share/tigervnc/*.log 2>/dev/null || ls -la /home/*/.vnc/*.log 2>/dev/null
systemctl restart wazuh-agent
```

* **Validation:** `grep "tigervnc" /var/ossec/logs/ossec.log` shows `Analyzing file: '/home/user1/.local/share/tigervnc/vnc-server:1.log'` for each active VNC user.

---

## 11. Automatic Monitoring of Newly Created Linux Users

### 11.1 How New Users Are Monitored Automatically

1. **Standard SSH & Non-Chroot SFTP Users (`useradd -m -s /bin/bash newuser5`):**
   * Automatically monitored **immediately** with zero extra commands.
   * SSH logins/failures log to `/var/log/secure`.
   * SFTP transfers log via global `Subsystem sftp internal-sftp -f AUTHPRIV -l INFO -u 0022` to `/var/log/secure`.
   * Commands executed log via kernel `auditd` (`auid >= 1000`) to `/var/log/audit/audit.log`.
2. **SFTP-Denied Users (`useradd -m -s /bin/bash -G sftp-denied newuser6`):**
   * Automatically monitored **immediately** with zero extra commands.
3. **Chrooted SFTP-Allowed Users (`useradd -m -s /bin/bash -G sftp-allowed newuser7`):**
   * Because OpenSSH `ChrootDirectory /srv/sftp/%u` requires a root-owned `/srv/sftp/<username>` directory and a `/srv/sftp/<username>/dev/log` socket, we install a lightweight helper script (`/usr/local/sbin/setup-sftp-chroot-user.sh`) so provisioning any future chrooted SFTP user takes one command.

### 11.2 Create the Helper Script for Future Chrooted SFTP Users

* **Location:** Wazuh Agent (`vnc-server`)
* **Execution user:** `root`
* **Purpose:** Create `/usr/local/sbin/setup-sftp-chroot-user.sh` to automatically set up the chroot directory, SELinux context, and `/dev/log` mount for any new `sftp-allowed` user.

```bash
cat << 'EOF' > /usr/local/sbin/setup-sftp-chroot-user.sh
#!/bin/bash
set -e
USERNAME="$1"
if [ -z "$USERNAME" ] || ! id "$USERNAME" >/dev/null 2>&1; then
    echo "Usage: $0 <existing-linux-username>"
    exit 1
fi

usermod -aG sftp-allowed "$USERNAME"
mkdir -p "/srv/sftp/${USERNAME}/dev" "/srv/sftp/${USERNAME}/files"
chown root:root /srv /srv/sftp "/srv/sftp/${USERNAME}" "/srv/sftp/${USERNAME}/dev"
chmod 755 /srv /srv/sftp "/srv/sftp/${USERNAME}" "/srv/sftp/${USERNAME}/dev"
chown "${USERNAME}:sftp-allowed" "/srv/sftp/${USERNAME}/files"
chmod 700 "/srv/sftp/${USERNAME}/files"

touch "/srv/sftp/${USERNAME}/dev/log"
if ! grep -q "/srv/sftp/${USERNAME}/dev/log" /proc/mounts; then
    mount --bind /run/systemd/journal/dev-log "/srv/sftp/${USERNAME}/dev/log"
fi
grep -q "/srv/sftp/${USERNAME}/dev/log" /etc/fstab || \
    echo "/run/systemd/journal/dev-log /srv/sftp/${USERNAME}/dev/log none bind 0 0" >> /etc/fstab

restorecon -Rv "/srv/sftp/${USERNAME}" >/dev/null 2>&1 || true
echo "Chroot SFTP and Wazuh /dev/log socket configured for ${USERNAME}."
EOF

chmod 750 /usr/local/sbin/setup-sftp-chroot-user.sh
```

* **Validation:** `ls -l /usr/local/sbin/setup-sftp-chroot-user.sh` shows `-rwxr-x---`.

---

## 12. Custom Decoders

Create `/var/ossec/etc/decoders/sftp_decoders.xml` on the Wazuh Manager to decode:
* SFTP session open/close (`sshd` and `sftp-server`)
* SFTP file `open`, `close` (bytes read/written), `remove`, `rmdir`, `rename`, `setstat`
* SFTP `forced-command` denials (`/usr/sbin/nologin` and `/usr/bin/false`)
* TigerVNC `Xvnc` connection accepted, authentication failure, and disconnection logs (extracting `srcip` and `srcport`)

### 12.1 Deploy `/var/ossec/etc/decoders/sftp_decoders.xml`

* **Location:** Wazuh Manager (`ec2-user`)
* **Execution user:** `root`
* **Purpose:** Install PCRE2 decoders for OpenSSH `internal-sftp`, SFTP access denials, and TigerVNC `Xvnc` logs.

```bash
cat << 'EOF' > /var/ossec/etc/decoders/sftp_decoders.xml
<decoder name="sftp-server">
  <program_name>^sftp-server|^internal-sftp</program_name>
</decoder>

<!-- 1. SFTP Decoders under program_name sftp-server / internal-sftp -->
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

<decoder name="sftp-server-file">
  <parent>sftp-server</parent>
  <prematch type="pcre2">^open "</prematch>
  <regex type="pcre2">^open "([^"]+)" flags (\S+) mode</regex>
  <order>file, extra_data</order>
</decoder>

<decoder name="sftp-server-close">
  <parent>sftp-server</parent>
  <prematch type="pcre2">^close "</prematch>
  <regex type="pcre2">^close "([^"]+)" bytes read (\d+) written (\d+)</regex>
  <order>file, status, extra_data</order>
</decoder>

<decoder name="sftp-server-modify">
  <parent>sftp-server</parent>
  <prematch type="pcre2">^(?:remove|rmdir|setstat) name "|^rename old "</prematch>
  <regex type="pcre2">^(?:remove name|rmdir name|setstat name|rename old) "([^"]+)"</regex>
  <order>file</order>
</decoder>

<!-- 2. SFTP Decoders under parent sshd (RHEL 9 internal-sftp default) -->
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

<decoder name="sshd-sftp-file">
  <parent>sshd</parent>
  <prematch type="pcre2">^open "</prematch>
  <regex type="pcre2">^open "([^"]+)" flags (\S+) mode</regex>
  <order>file, extra_data</order>
</decoder>

<decoder name="sshd-sftp-close">
  <parent>sshd</parent>
  <prematch type="pcre2">^close "</prematch>
  <regex type="pcre2">^close "([^"]+)" bytes read (\d+) written (\d+)</regex>
  <order>file, status, extra_data</order>
</decoder>

<decoder name="sshd-sftp-modify">
  <parent>sshd</parent>
  <prematch type="pcre2">^(?:remove|rmdir|setstat) name "|^rename old "</prematch>
  <regex type="pcre2">^(?:remove name|rmdir name|setstat name|rename old) "([^"]+)"</regex>
  <order>file</order>
</decoder>

<!-- 3. Blocked SFTP User Decoder (Match Group sftp-denied -> forced-command nologin or false) -->
<decoder name="sshd-sftp-blocked">
  <parent>sshd</parent>
  <prematch type="pcre2">forced-command \(config\) '/usr/(?:sbin/nologin|bin/false)'</prematch>
  <regex type="pcre2">forced-command \(config\) '/usr/(?:sbin/nologin|bin/false)' for (\S+) from (\S+) port (\d+)</regex>
  <order>dstuser, srcip, srcport</order>
</decoder>

<!-- 4. TigerVNC Xvnc Log Decoders -->
<decoder name="tigervnc-xvnc">
  <prematch type="pcre2">^\s*(?:Connections:\s+(?:accepted|closed):|vncext:\s+)</prematch>
</decoder>

<decoder name="tigervnc-xvnc-conn">
  <parent>tigervnc-xvnc</parent>
  <regex type="pcre2">Connections:\s+(accepted|closed):\s+([0-9a-fA-F:.]+)::(\d+)</regex>
  <order>status, srcip, srcport</order>
</decoder>
EOF

chown wazuh:wazuh /var/ossec/etc/decoders/sftp_decoders.xml
chmod 660 /var/ossec/etc/decoders/sftp_decoders.xml
```

* **Validation:** Run `/var/ossec/bin/wazuh-analysisd -t` and confirm zero syntax errors.

---

## 13. Custom Rules (SFTP & TigerVNC)

### 13.1 Why Previously Uploading One File Sent 3 Duplicate Emails

When `user1` uploaded a single file (`put chip.gds`), three events fired simultaneously:
1. `Rule 100502`: `open "/files/chip.gds" flags WRITE,CREATE,TRUNCATE`
2. `Rule 100507`: `close "/files/chip.gds" bytes read 0 written 46`
3. `Rule 100512` (or `550`/`554`): Syscheck FIM file creation alert

Because all three rules were in `notify_sftp_transfer`, Wazuh sent **3 emails for 1 file upload**!
* **How We Fix It:**
  * `Rule 100502` (file opened for writing) and `Rule 100503` (file opened for reading) are placed in `sftp_file_open` (logged to Dashboard, caches the operation type in our session tracker, **does not send a premature email**).
  * `Rule 100507` (`close "..." bytes read X written Y`) is the **authoritative SFTP Transfer Completed alert (`notify_sftp_transfer`)** and sends **1 single email** per uploaded or downloaded file with the exact byte count!
  * `Rule 100504` (`remove`, `rmdir`, `rename`) sends **1 email** when a file is deleted or renamed via SFTP.
  * `Rule 100505` (user in `sftp-denied` blocked from SFTP) and `Rule 100508` (`Permission denied` during file upload/download) are in `notify_sftp_denied` and send **1 High-severity email**.

### 13.2 Deploy `/var/ossec/etc/rules/sftp_and_vnc_rules.xml`

* **Location:** Wazuh Manager (`ec2-user`)
* **Execution user:** `root`
* **Purpose:** Configure clean, non-overlapping SFTP and TigerVNC rules.

```bash
cat << 'EOF' > /var/ossec/etc/rules/sftp_and_vnc_rules.xml
<group name="sftp_monitoring,">

  <!-- 1. SFTP Session Opened & Closed (Caches PID -> Username & Source IP; No Email by Default) -->
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

  <!-- 2. SFTP File Open (Upload/Download Initiated - Logged in Dashboard & Caches File/Op) -->
  <rule id="100502" level="6">
    <match>flags WRITE|flags CREATE|flags TRUNCATE|flags APPEND|flags READ,WRITE</match>
    <description>SFTP File Upload Initiated: File "$(file)" opened with flags $(extra_data)</description>
    <group>sftp_session,sftp_upload_open,</group>
  </rule>

  <rule id="100503" level="6">
    <match>flags READ mode</match>
    <description>SFTP File Download Initiated: File "$(file)" opened for reading</description>
    <group>sftp_session,sftp_download_open,</group>
  </rule>

  <!-- 3. SFTP File Transfer Completed (Triggers 1 Authoritative Email for Upload or Download) -->
  <rule id="100507" level="8">
    <regex type="pcre2">^close "[^"]+" bytes read (?:[1-9]\d* written \d+|0 written [1-9]\d*)</regex>
    <description>SFTP File Transfer Detected: File "$(file)" transferred (Bytes read: $(status), Bytes written: $(extra_data))</description>
    <group>sftp_transfer,sftp_completed,notify_sftp_transfer,</group>
  </rule>

  <!-- 4. SFTP File Deleted or Renamed (Triggers 1 Authoritative Email) -->
  <rule id="100504" level="10">
    <regex>remove name "|rmdir name "|rename old "</regex>
    <description>SFTP File Deletion or Rename Detected on "$(file)"</description>
    <group>sftp_transfer,sftp_delete_rename,notify_sftp_transfer,</group>
  </rule>

  <!-- 5. SFTP Access Denied for Restricted User (sftp-denied group) -->
  <rule id="100505" level="12">
    <if_group>sshd</if_group>
    <match>not allowed because a group is listed in DenyGroups|Forced command '/usr/sbin/nologin'|forced-command (config) '/usr/sbin/nologin'|Forced command '/usr/bin/false'|forced-command (config) '/usr/bin/false'|subsystem request for sftp failed</match>
    <description>SFTP Access Denied: Restricted user $(dstuser) from IP $(srcip) attempted SFTP access</description>
    <group>authentication_failed,sftp_denied,notify_sftp_denied,</group>
  </rule>

  <!-- 6. SFTP File Operation Failed / Permission Denied -->
  <rule id="100508" level="11">
    <match>sent status Permission denied|sent status Failure</match>
    <description>SFTP File Operation Failed/Denied: SFTP server returned Permission denied</description>
    <group>sftp_denied,sftp_operation_failed,notify_sftp_denied,</group>
  </rule>

  <!-- 7. TigerVNC Configuration, Session & Authentication Monitoring -->
  <rule id="100506" level="10">
    <if_sid>80700</if_sid>
    <field name="audit.key">vnc-config-modify</field>
    <description>TigerVNC Configuration Modified by user AUID $(audit.auid)</description>
    <group>vnc_monitoring,notify_vnc,</group>
  </rule>

  <rule id="100509" level="5">
    <decoded_as>tigervnc-xvnc</decoded_as>
    <match>Connections: accepted:</match>
    <description>TigerVNC Client Connected from IP $(srcip) port $(srcport)</description>
    <group>authentication_success,vnc_monitoring,notify_vnc,</group>
  </rule>

  <rule id="100510" level="9">
    <decoded_as>tigervnc-xvnc</decoded_as>
    <match>AuthFailureException|Authentication failure|blacklist</match>
    <description>TigerVNC Authentication Failed from IP $(srcip) port $(srcport)</description>
    <group>authentication_failed,vnc_monitoring,notify_vnc,</group>
  </rule>

  <rule id="100513" level="4">
    <decoded_as>tigervnc-xvnc</decoded_as>
    <match>Connections: closed:</match>
    <description>TigerVNC Client Disconnected from IP $(srcip) port $(srcport)</description>
    <group>vnc_monitoring,</group>
  </rule>

</group>
EOF

chown wazuh:wazuh /var/ossec/etc/rules/sftp_and_vnc_rules.xml
chmod 660 /var/ossec/etc/rules/sftp_and_vnc_rules.xml
```

* **Validation:** Run `/var/ossec/bin/wazuh-analysisd -t` and confirm zero errors.

---

## 14. Brute-Force Correlation & SSH/Network Rules

### 14.1 How Wazuh Correlation, Frequency, Timeframe, and Hierarchy Work

1. **Why 2 Emails Fired Previously on Brute-Force:**
   Previously, we had two separate rules at the same level: `100601` (`<same_source_ip />`) and `100602` (`<same_user />`). Because both rules matched `authentication_failed` independently, Wazuh evaluated the 5th failed login against `100601` (or `100602`), and then the 6th failed login matched the other rule, or both rules fired in the same batch.
2. **Unified Correlation by `<same_source_ip />` with Dynamic `$(dstuser)`:**
   By consolidating the 5-attempt Medium threshold into **one authoritative rule (`100601`, `frequency="5"`, `timeframe="300"`)** and the 10-attempt High threshold into **one authoritative rule (`100611`, `frequency="10"`, `timeframe="300"`)**—and placing `100611` **before** `100601` while keeping `authentication_failed` in `100601`'s `<group>` list—Wazuh counts every failed password attempt cleanly:
   * **Attempts 1–4:** Match built-in `5716` / `5710` (Level 5, no email).
   * **Attempt 5:** Matches `100601` (Level 8, **Medium Severity**) -> Sends **1 Medium Email**.
   * **Attempts 6–9:** Match `100601` in Wazuh, suppressed by our integration deduplication guard -> **0 Emails**.
   * **Attempt 10:** Matches `100611` (Level 12, **High Severity**, evaluated before `100601`) -> Sends **1 High Escalation Email**.

### 14.2 Deploy `/var/ossec/etc/rules/ssh_and_network_rules.xml`

* **Location:** Wazuh Manager (`ec2-user`)
* **Execution user:** `root`
* **Purpose:** Configure the 5-attempt Medium and 10-attempt High SSH brute-force rules, suspicious SSH login rules, user/group audit rules, and network rules.

```bash
cat << 'EOF' > /var/ossec/etc/rules/ssh_and_network_rules.xml
<group name="ssh_security_monitoring,network_security_monitoring,">

  <!-- ========================================================================= -->
  <!-- HIGH SEVERITY: 10 Failed SSH Attempts Within 5 Minutes (300s)             -->
  <!-- Placed BEFORE Rule 100601 so attempt #10 matches High Severity first      -->
  <!-- ========================================================================= -->
  <rule id="100611" level="12" frequency="10" timeframe="300">
    <if_matched_group>authentication_failed</if_matched_group>
    <same_source_ip />
    <description>SSH Brute-Force Attack Detected: 10 failed login attempts within 5 minutes from IP $(srcip) targeting user $(dstuser)</description>
    <mitre>
      <id>T1110.001</id>
    </mitre>
    <group>authentication_failed,authentication_failures,ssh_brute_force_high,notify_ssh_bruteforce,</group>
  </rule>

  <!-- ========================================================================= -->
  <!-- MEDIUM SEVERITY: 5 Failed SSH Attempts Within 5 Minutes (300s)            -->
  <!-- Retains 'authentication_failed' group so attempts 5-9 keep counting to 10 -->
  <!-- ========================================================================= -->
  <rule id="100601" level="8" frequency="5" timeframe="300">
    <if_matched_group>authentication_failed</if_matched_group>
    <same_source_ip />
    <description>SSH Brute-Force Activity Detected: 5 failed login attempts within 5 minutes from IP $(srcip) targeting user $(dstuser)</description>
    <mitre>
      <id>T1110.001</id>
    </mitre>
    <group>authentication_failed,authentication_failures,ssh_brute_force_medium,notify_ssh_bruteforce,</group>
  </rule>

  <!-- ========================================================================= -->
  <!-- SUSPICIOUS SSH ACTIVITY (Configurable Category: notify_ssh_suspicious)    -->
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
    <description>SSH Username Enumeration Detected: Source IP $(srcip) failed authentication against multiple distinct usernames within 5 minutes (latest user: $(dstuser))</description>
    <mitre>
      <id>T1110.003</id>
    </mitre>
    <group>authentication_failures,ssh_enumeration,notify_ssh_suspicious,</group>
  </rule>

  <rule id="100605" level="14" timeframe="300">
    <if_sid>5715</if_sid>
    <if_matched_group>notify_ssh_bruteforce</if_matched_group>
    <same_source_ip />
    <description>CRITICAL: Successful SSH login by user $(dstuser) from IP $(srcip) immediately following an SSH brute-force incident</description>
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

</group>
EOF

chown wazuh:wazuh /var/ossec/etc/rules/ssh_and_network_rules.xml
chmod 660 /var/ossec/etc/rules/ssh_and_network_rules.xml
```

* **Validation:** Run `/var/ossec/bin/wazuh-analysisd -t` and confirm zero errors.

---

## 15. Email Notification Policy

All security events remain visible in the Wazuh Dashboard. Email notifications are controlled by `/var/ossec/etc/email_notification_policy.json`.

### 15.1 Create `/var/ossec/etc/email_notification_policy.json`

* **Location:** Wazuh Manager (`ec2-user`)
* **Execution user:** `root`
* **Purpose:** Configure default enabled email categories (SFTP transfers, SFTP denied/failed, and SSH brute-force) and disable noisy categories by default.

```bash
cat << 'EOF' > /var/ossec/etc/email_notification_policy.json
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
  "cooldown_seconds": {
    "ssh_bruteforce_medium": 300,
    "ssh_bruteforce_high": 300,
    "sftp_transfer_same_file": 15,
    "sftp_denied_same_user": 60
  }
}
EOF

chown root:wazuh /var/ossec/etc/email_notification_policy.json
chmod 660 /var/ossec/etc/email_notification_policy.json
```

* **Validation:** `cat /var/ossec/etc/email_notification_policy.json` displays the JSON policy.

---

## 16. Duplicate Email Prevention Architecture

Our notification engine (`/var/ossec/integrations/custom-html-email.py`) prevents duplicate emails using four mechanisms:
1. **File Lock Serialization (`fcntl.flock`):** When multiple events arrive in the same millisecond, `wazuh-integratord` spawns concurrent processes. An exclusive file lock (`/var/ossec/tmp/sftp_session_cache.lock`) ensures two processes never race or send duplicate emails simultaneously.
2. **Incident Fingerprint Identification:**
   * **Brute-Force Medium (`Rule 100601`):** Keyed by `bf:MEDIUM:<agent_id>:<srcip>:<dstuser>` with a `300s` (5-minute) cooldown. Attempts #6–#9 are suppressed after Attempt #5 sends the Medium email.
   * **Brute-Force High (`Rule 100611`):** Keyed by `bf:HIGH:<agent_id>:<srcip>:<dstuser>` with a `300s` cooldown. Because its tier is `HIGH`, Attempt #10 is **not** blocked by the earlier `MEDIUM` cooldown and sends 1 High Escalation email immediately.
   * **SFTP File Transfer (`Rule 100507` / `100504`):** Keyed by `sftp:<agent_id>:<dstuser>:<operation>:<file_path>` with a `15s` cooldown so a single file transfer only sends **1 email**, while uploading a different file or another user uploading a file is never suppressed.
   * **SFTP Access Denied (`Rule 100505` / `100508`):** Keyed by `denied:<agent_id>:<dstuser>:<srcip>:<rule_id>` with a `60s` cooldown to prevent notification storms if an SFTP client auto-retries a blocked connection.

---

## 17. Postfix Installation and Gmail SMTP Configuration

Configure Postfix on the Wazuh Manager to relay all outbound emails through `smtp.gmail.com:587` over IPv4 with STARTTLS and a Gmail App Password.

### 17.1 Install and Configure Postfix with SASL App Password Authentication

* **Location:** Wazuh Manager (`ec2-user`)
* **Execution user:** `root`
* **Purpose:** Install Postfix and Cyrus SASL, configure Gmail STARTTLS relay, and secure `/etc/postfix/sasl_passwd` and `/etc/postfix/sasl_passwd.db`.

```bash
SMTP_HOST="smtp.gmail.com"
SMTP_PORT="587"
SMTP_USERNAME="devops.jakir@gmail.com"
SMTP_APP_PASSWORD="<GMAIL_APP_PASSWORD>"

# 1. Install required packages
dnf install -y postfix cyrus-sasl cyrus-sasl-plain s-nail
systemctl enable --now postfix

# 2. Configure Postfix parameters using postconf (automatically deduplicates main.cf entries)
postconf -e "inet_protocols = ipv4"
postconf -e "relayhost = [${SMTP_HOST}]:${SMTP_PORT}"
postconf -e "smtp_use_tls = yes"
postconf -e "smtp_sasl_auth_enable = yes"
postconf -e "smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd"
postconf -e "smtp_sasl_security_options = noanonymous"
postconf -e "smtp_tls_security_level = encrypt"
postconf -e "smtp_tls_cafile = /etc/ssl/certs/ca-bundle.crt"

# 3. Create the SASL credentials file and hash database with strict 0600 permissions
cat << EOF > /etc/postfix/sasl_passwd
[${SMTP_HOST}]:${SMTP_PORT} ${SMTP_USERNAME}:${SMTP_APP_PASSWORD}
EOF

chown root:root /etc/postfix/sasl_passwd
chmod 600 /etc/postfix/sasl_passwd
postmap /etc/postfix/sasl_passwd
chown root:root /etc/postfix/sasl_passwd.db
chmod 600 /etc/postfix/sasl_passwd.db

# 4. Validate Postfix configuration and restart
postfix check && systemctl restart postfix
```

* **Validation:**
  ```bash
  ls -l /etc/postfix/sasl_passwd /etc/postfix/sasl_passwd.db
  postqueue -p
  echo "Postfix STARTTLS verification test" | mail -s "Wazuh SMTP Relay Test" "hiddenclue0@gmail.com"
  sleep 3
  tail -n 15 /var/log/maillog
  ```
  Verify `/var/log/maillog` shows `relay=smtp.gmail.com[...]:587 ... status=sent (250 2.0.0 OK ...)`.

---

## 18. Wazuh Email Integration (`custom-html-email.py`)

Deploy `/var/ossec/integrations/custom-html-email.py` on the Wazuh Manager.

### 18.1 Deploy `/var/ossec/integrations/custom-html-email.py`

* **Location:** Wazuh Manager (`ec2-user`)
* **Execution user:** `root`
* **Purpose:** Create the Python integration script with `fcntl` locking, PID session caching, TigerVNC path attribution, incident deduplication, and the 6-section HTML email template.

```bash
SMTP_USERNAME="devops.jakir@gmail.com"
ALERT_RECIPIENT_EMAIL="hiddenclue0@gmail.com"

cat << 'EOF' > /var/ossec/integrations/custom-html-email.py
#!/var/ossec/framework/python/bin/python3
# -*- coding: utf-8 -*-
"""
Wazuh v4.14.9 Production HTML Notification Engine
- File-locked PID & User session cache (/var/ossec/tmp/sftp_session_cache.json)
- Attributes chrooted SFTP users, standard SSH/SFTP users, and TigerVNC display users accurately
- Enforces configurable category policy and incident cooldown deduplication
"""

import os
import re
import sys
import json
import time
import html
import fcntl
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
LOCK_FILE = "/var/ossec/tmp/sftp_session_cache.lock"


def load_json(path, default_val):
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return default_val


def save_json(path, data):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = f"{path}.tmp.{os.getpid()}"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f)
        os.replace(tmp, path)
    except Exception:
        pass


def extract_pid(full_log):
    m = re.search(r"(?:sshd|sftp-server|internal-sftp)\[(\d+)\]:", full_log)
    return m.group(1) if m else None


def format_ts(ts_str):
    if not ts_str:
        return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    clean = ts_str.split(".")[0].replace("T", " ")
    return f"{clean} UTC" if not clean.endswith("UTC") else clean


def determine_category(rule_id, groups):
    rid = str(rule_id)
    if "notify_sftp_transfer" in groups or rid in ("100504", "100507"):
        return "sftp_successful_transfers"
    if "notify_sftp_denied" in groups or rid in ("100505", "100508"):
        return "sftp_failed_denied_operations"
    if "notify_ssh_bruteforce" in groups or rid in ("100601", "100611"):
        return "ssh_bruteforce_detection"
    if "notify_sftp_connect" in groups or rid in ("100501", "100511"):
        return "sftp_connection_attempts"
    if "notify_ssh_suspicious" in groups or rid in ("100603", "100604", "100605", "100606", "100607", "100608", "100610"):
        return "ssh_suspicious_login"
    if "notify_user_mgmt" in groups or rid in ("5902", "5903", "5904", "100630"):
        return "linux_user_creation_deletion"
    if "notify_group_mgmt" in groups or rid in ("5901", "100631"):
        return "linux_group_changes"
    if "notify_vnc" in groups or rid in ("100506", "100509", "100510"):
        return "vnc_session_events"
    if "syscheck" in groups:
        return "file_integrity_monitoring"
    if rid in ("5715", "5716", "5710"):
        return "ssh_authentication_events"
    return "other_security_alerts"


def update_and_resolve_context(cache, agent_id, rule_id, groups, full_log, location, srcip, dstuser, file_path, extra_data):
    now = int(time.time())
    sessions = cache.get("sessions", {})
    sessions = {k: v for k, v in sessions.items() if now - v.get("ts", 0) < 7200}

    vnc_display = None
    # 1. Extract Linux username & VNC display from TigerVNC log file path: /home/<user>/.local/share/tigervnc/<host>:<display>.log
    if location and ("tigervnc" in location or ".vnc" in location):
        m_vnc = re.search(r"/home/([^/]+)/.*:(\d+)\.log", location)
        if m_vnc:
            dstuser = dstuser or m_vnc.group(1)
            vnc_display = f":{m_vnc.group(2)}"

    # 2. Extract username from /srv/sftp/<user>/... or /home/<user>/... if present in file_path
    if not dstuser and file_path:
        if file_path.startswith("/srv/sftp/"):
            parts = file_path.split("/")
            if len(parts) >= 4 and parts[3]:
                dstuser = parts[3]
        elif file_path.startswith("/home/"):
            parts = file_path.split("/")
            if len(parts) >= 3 and parts[2]:
                dstuser = parts[2]

    # 3. Check raw syslog text for username and source IP if decoder did not populate them
    if not dstuser:
        m_u = re.search(r"(?:for local user |for invalid user |user=|\bfor )([a-zA-Z0-9_.-]+)", full_log)
        if m_u and m_u.group(1) not in ("from", "port", "id"):
            dstuser = m_u.group(1)
    if not srcip:
        m_ip = re.search(r"from \[?([0-9a-fA-F:.]+)\]?", full_log)
        if m_ip:
            srcip = m_ip.group(1)

    # 4. Correlate by OpenSSH / internal-sftp PID
    pid = extract_pid(full_log)
    skey = f"{agent_id}:{pid}" if pid else None
    last_op = None

    if skey:
        entry = sessions.get(skey, {"ts": now})
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

        if str(rule_id) == "100502":
            entry["op"] = "Upload"
        elif str(rule_id) == "100503":
            entry["op"] = "Download"
        last_op = entry.get("op")
        sessions[skey] = entry

    cache["sessions"] = sessions
    return srcip, dstuser, file_path, vnc_display, last_op


def is_duplicate_incident(cache, dedup_key, cooldown_sec):
    now = int(time.time())
    dedup = cache.get("dedup", {})
    dedup = {k: v for k, v in dedup.items() if now - v < 3600}
    last_ts = dedup.get(dedup_key, 0)
    if now - last_ts < cooldown_sec:
        cache["dedup"] = dedup
        return True
    dedup[dedup_key] = now
    cache["dedup"] = dedup
    return False


def build_template_data(rule_id, rule_level, groups, srcip, dstuser, file_path, extra_data, status_val, vnc_display, last_op, full_log):
    rid = str(rule_id)
    u_disp = dstuser or "Unknown User"
    ip_disp = srcip or "Unknown IP"
    fname = os.path.basename(file_path) if file_path else None

    access_method = "SSH"
    auth_status = "Authenticated"
    operation = None
    transfer_result = None
    failed_attempts = None
    user_group = None

    if rid == "100601":
        severity = "MEDIUM"
        incident_name = "SSH Brute-Force Activity Detected"
        auth_status = "Failed (5 Unsuccessful Attempts)"
        failed_attempts = "5 failed attempts within 5 minutes"
        summary = f"Five unsuccessful SSH login attempts were detected targeting user '{u_disp}' from source IP {ip_disp} within five minutes."
        explanation = "Five unsuccessful SSH login attempts were detected from the same source IP within five minutes. This activity may indicate an attempt to gain unauthorized access."
        actions = [
            f"Verify whether user '{u_disp}' is authorized and mistyped their password.",
            f"Review the source IP address ({ip_disp}).",
            "Check whether any successful login followed the failed attempts.",
            "Contact the system administrator if the activity is suspicious."
        ]

    elif rid == "100611":
        severity = "HIGH"
        incident_name = "SSH Brute-Force Attack Detected"
        auth_status = "Failed (10 Unsuccessful Attempts)"
        failed_attempts = "10 failed attempts within 5 minutes"
        summary = f"Ten unsuccessful SSH login attempts were detected targeting user '{u_disp}' from source IP {ip_disp} within five minutes."
        explanation = "Ten unsuccessful SSH login attempts were recorded within five minutes, escalating the earlier medium-severity alert to a high-severity brute-force attack."
        actions = [
            f"Immediately verify whether source IP {ip_disp} is unauthorized.",
            f"Check whether any successful login followed the failed attempts for '{u_disp}'.",
            f"Block source IP {ip_disp} at the firewall or AWS Security Group if unauthorized.",
            "Contact the system administrator immediately."
        ]

    elif rid == "100507":
        severity = "MEDIUM"
        incident_name = "SFTP File Transfer Detected"
        access_method = "SFTP"
        user_group = "sftp-allowed"
        written = int(extra_data) if str(extra_data).isdigit() else 0
        read_b = int(status_val) if str(status_val).isdigit() else 0
        if written > 0 or last_op == "Upload":
            operation = f"Upload ({written} bytes written)" if written > 0 else "Upload"
            verb = "uploaded"
            prep = "to"
        else:
            operation = f"Download ({read_b} bytes read)" if read_b > 0 else "Download"
            verb = "downloaded"
            prep = "from"
        transfer_result = "Completed Successfully"
        summary = f"User '{u_disp}' successfully {verb} a file ('{fname or 'file'}') {prep} the monitored server through SFTP. The activity was recorded for security auditing."
        explanation = f"An authenticated SFTP session completed a file {operation.lower()} operation on the monitored server."
        actions = [
            f"Verify whether user '{u_disp}' is authorized to transfer '{fname or file_path}'.",
            f"Review the source IP address ({ip_disp}).",
            "Contact the system administrator if the file transfer was unexpected."
        ]

    elif rid == "100504":
        severity = "MEDIUM"
        incident_name = "SFTP File Modification or Deletion Detected"
        access_method = "SFTP"
        operation = "Delete" if ("remove " in full_log or "rmdir " in full_log) else "Rename"
        transfer_result = "Completed"
        summary = f"User '{u_disp}' performed an SFTP {operation.lower()} operation on '{fname or file_path}'."
        explanation = "A file or directory on the SFTP server was deleted or renamed by an authenticated user."
        actions = [
            f"Verify whether user '{u_disp}' was authorized to {operation.lower()} '{fname or file_path}'.",
            f"Review the source IP address ({ip_disp}).",
            "Contact the system administrator if the deletion or rename was unauthorized."
        ]

    elif rid == "100505":
        severity = "HIGH"
        incident_name = "SFTP Access Denied"
        access_method = "SFTP"
        auth_status = "Denied (Restricted Account)"
        user_group = "sftp-denied"
        operation = "Unauthorized SFTP Connection Attempt"
        transfer_result = "Denied by Server Policy"
        summary = f"Restricted user '{u_disp}' attempted an SFTP/SSH connection from {ip_disp} and was blocked by server policy."
        explanation = "This user account belongs to the 'sftp-denied' group (VNC-only access) and is prohibited from transferring files over SFTP."
        actions = [
            f"Verify why user '{u_disp}' attempted SFTP access from {ip_disp}.",
            "Remind the employee that their account is restricted to VNC desktop access only.",
            "Contact the system administrator if unauthorized data exfiltration is suspected."
        ]

    elif rid == "100508":
        severity = "HIGH"
        incident_name = "SFTP File Transfer Denied"
        access_method = "SFTP"
        operation = "File Access / Upload Attempt"
        transfer_result = "Failed (Permission Denied)"
        summary = f"User '{u_disp}' attempted an SFTP file operation that was rejected due to insufficient filesystem permissions."
        explanation = "The SFTP server returned 'Permission denied' when the user attempted to read, write, or delete a restricted path."
        actions = [
            f"Verify whether user '{u_disp}' attempted to write outside their authorized '/files' directory.",
            f"Review the source IP address ({ip_disp}).",
            "Contact the system administrator if the activity is suspicious."
        ]

    elif rid in ("100506", "100509", "100510"):
        severity = "HIGH" if rid == "100510" else "MEDIUM"
        incident_name = "TigerVNC Authentication Failed" if rid == "100510" else "TigerVNC Session Activity Detected"
        access_method = f"VNC ({vnc_display})" if vnc_display else "VNC"
        auth_status = "Failed" if rid == "100510" else "Authenticated"
        summary = f"TigerVNC remote desktop activity ({incident_name}) was recorded for user '{u_disp}' from {ip_disp}."
        explanation = "TigerVNC remote desktop connections are monitored to track graphical session access across engineering displays."
        actions = [
            f"Verify whether user '{u_disp}' initiated the VNC connection from {ip_disp}.",
            "Contact the system administrator if the VNC session activity is unexpected."
        ]

    else:
        severity = "HIGH" if rule_level >= 11 else "MEDIUM"
        incident_name = rule_id and f"Security Event Detected (Rule {rid})" or "Security Event Detected"
        summary = f"Wazuh detected a security event involving user '{u_disp}' on the monitored server."
        explanation = "This event matched an active security rule enabled in the notification policy."
        actions = [
            "Verify whether the user and source IP address are authorized.",
            "Contact the system administrator if the activity is suspicious."
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


def render_html_rows(rows):
    out = []
    for label, val, style in rows:
        if val is None or str(val).strip() in ("", "N/A", "Unknown User", "Unknown IP"):
            continue
        sval = html.escape(str(val))
        if style == "red":
            v_html = f"<span style='color:#b91c1c;font-weight:700;'>{sval}</span>"
        elif style == "code":
            v_html = f"<code style='background:#f3f4f6;padding:2px 6px;border-radius:4px;font-family:monospace;font-size:13px;color:#111827;font-weight:600;'>{sval}</code>"
        elif style == "bold":
            v_html = f"<strong style='color:#111827;'>{sval}</strong>"
        else:
            v_html = sval
        out.append(
            f"<tr>"
            f"<td width='36%' style='padding:7px 10px;font-weight:600;color:#4b5563;border-bottom:1px solid #f3f4f6;'>{html.escape(label)}</td>"
            f"<td style='padding:7px 10px;color:#1f2937;border-bottom:1px solid #f3f4f6;'>{v_html}</td>"
            f"</tr>"
        )
    return "".join(out)


def render_text_rows(rows):
    return "\n".join(
        f"- {label}: {val}"
        for label, val, _ in rows
        if val is not None and str(val).strip() not in ("", "N/A", "Unknown User", "Unknown IP")
    )


def main():
    if len(sys.argv) < 2:
        sys.exit(0)

    try:
        with open(sys.argv[1], "r", encoding="utf-8") as f:
            alert = json.load(f)
    except Exception:
        sys.exit(1)

    os.makedirs(os.path.dirname(LOCK_FILE), exist_ok=True)
    lock_fd = open(LOCK_FILE, "w")
    fcntl.flock(lock_fd, fcntl.LOCK_EX)

    try:
        rule = alert.get("rule", {})
        agent = alert.get("agent", {})
        data = alert.get("data", {})

        rule_id = str(rule.get("id", ""))
        rule_level = int(rule.get("level", 0))
        groups = rule.get("groups", [])
        full_log = alert.get("full_log", "")
        location = alert.get("location", "")

        agent_name = agent.get("name", "vnc-server")
        agent_id = agent.get("id", "001")
        agent_ip = agent.get("ip", "127.0.0.1")

        # Note: Do NOT fall back to syscheck.audit.user.name on SFTP events to prevent 'ec2-user' auid misattribution
        srcip = data.get("srcip")
        srcport = data.get("srcport")
        dstuser = data.get("dstuser") or data.get("srcuser")
        uid_val = data.get("uid") or data.get("audit", {}).get("uid")
        file_path = data.get("file")
        extra_data = data.get("extra_data")
        status_val = data.get("status")

        cache = load_json(CACHE_FILE, {"sessions": {}, "dedup": {}})
        srcip, dstuser, file_path, vnc_display, last_op = update_and_resolve_context(
            cache, agent_id, rule_id, groups, full_log, location, srcip, dstuser, file_path, extra_data
        )
        save_json(CACHE_FILE, cache)

        # SFTP file open rules (100502/100503) only update the cache; Rule 100507 sends the transfer email
        if rule_id in ("100502", "100503"):
            sys.exit(0)

        policy = load_json(POLICY_FILE, {})
        categories = policy.get("categories", {
            "sftp_successful_transfers": True,
            "sftp_failed_denied_operations": True,
            "ssh_bruteforce_detection": True,
        })
        cooldowns = policy.get("cooldown_seconds", {})

        cat_key = determine_category(rule_id, groups)
        if not categories.get(cat_key, False):
            sys.exit(0)

        # Deduplication check per incident type
        if rule_id == "100601":
            dkey = f"bf:MEDIUM:{agent_id}:{srcip}:{dstuser}"
            cd = int(cooldowns.get("ssh_bruteforce_medium", 300))
        elif rule_id == "100611":
            dkey = f"bf:HIGH:{agent_id}:{srcip}:{dstuser}"
            cd = int(cooldowns.get("ssh_bruteforce_high", 300))
        elif rule_id in ("100507", "100504"):
            dkey = f"sftp:{agent_id}:{dstuser}:{rule_id}:{file_path}"
            cd = int(cooldowns.get("sftp_transfer_same_file", 15))
        elif rule_id in ("100505", "100508"):
            dkey = f"denied:{agent_id}:{dstuser}:{srcip}:{rule_id}"
            cd = int(cooldowns.get("sftp_denied_same_user", 60))
        else:
            dkey = f"gen:{agent_id}:{rule_id}:{dstuser}:{srcip}"
            cd = 60

        if is_duplicate_incident(cache, dkey, cd):
            save_json(CACHE_FILE, cache)
            sys.exit(0)

        save_json(CACHE_FILE, cache)
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        lock_fd.close()

    info = build_template_data(
        rule_id, rule_level, groups, srcip, dstuser, file_path, extra_data, status_val, vnc_display, last_op, full_log
    )

    severity = info["severity"]
    incident_name = info["incident_name"]
    badge_color = "#b91c1c" if severity == "HIGH" else "#d97706"
    bg_tint = "#fef2f2" if severity == "HIGH" else "#fffbeb"
    ts_fmt = format_ts(alert.get("timestamp"))
    fname = os.path.basename(file_path) if file_path else None

    subject = f"[{severity}] {incident_name} | {agent_name}"

    server_rows = [
        ("Server Hostname", agent_name, "bold"),
        ("Server IP Address", agent_ip, "code"),
        ("Wazuh Agent Name", agent_name, None),
        ("Wazuh Agent ID", agent_id, None),
        ("Operating System", "Red Hat Enterprise Linux 9.8", None),
    ]

    user_rows = [
        ("Username", dstuser, "bold"),
        ("User ID (UID)", uid_val, None),
        ("User Group", info["user_group"], None),
        ("Access Method", info["access_method"], "bold"),
        ("Authentication Status", info["auth_status"], "red" if ("Failed" in info["auth_status"] or "Denied" in info["auth_status"]) else "bold"),
    ]

    if info["access_method"].startswith("SFTP"):
        activity_rows = [
            ("Source IP", srcip, "red"),
            ("Username", dstuser, "bold"),
            ("File Name", fname, "code"),
            ("Full File Path", file_path, "code"),
            ("Operation", info["operation"], "bold"),
            ("Transfer Result", info["transfer_result"], "red" if (info["transfer_result"] and ("Denied" in info["transfer_result"] or "Failed" in info["transfer_result"])) else "bold"),
            ("Event Timestamp", ts_fmt, None),
        ]
    else:
        dest_port = "22 (SSH)" if info["access_method"] == "SSH" else srcport
        activity_rows = [
            ("Source IP", srcip, "red"),
            ("Destination Server", f"{agent_name} ({agent_ip})", "bold"),
            ("Destination Port", dest_port, None),
            ("Number of Failed Attempts", info["failed_attempts"], "red"),
            ("Authentication Result", info["auth_status"], "red" if "Failed" in info["auth_status"] else "bold"),
            ("Event Timestamp", ts_fmt, None),
        ]

    actions_html = "".join(f"<li style='margin-bottom:8px;'>{html.escape(a)}</li>" for a in info["actions"])
    actions_txt = "\n".join(f"{i+1}. {a}" for i, a in enumerate(info["actions"]))

    plain_body = f"""Security Incident Notification • {severity} Severity
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
{actions_txt}
========================================================================
"""

    html_body = f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:24px 12px;background-color:#f3f4f6;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial,sans-serif;color:#1f2937;">
  <table width="100%" cellpadding="0" cellspacing="0" style="max-width:680px;margin:0 auto;background-color:#ffffff;border:1px solid #e5e7eb;border-radius:10px;overflow:hidden;">
    <tr>
      <td style="background-color:{badge_color};color:#ffffff;padding:20px 26px;">
        <div style="font-size:13px;font-weight:700;letter-spacing:0.6px;text-transform:uppercase;">
          Security Incident Notification &bull; {html.escape(severity)} Severity
        </div>
        <div style="font-size:22px;font-weight:700;margin-top:6px;">
          {html.escape(incident_name)}
        </div>
      </td>
    </tr>
    <tr>
      <td style="padding:26px;">
        <h3 style="margin:0 0 10px 0;font-size:15px;color:#111827;border-bottom:2px solid #e5e7eb;padding-bottom:6px;">Section 1: Incident Summary</h3>
        <p style="margin:0 0 22px 0;font-size:15px;line-height:1.6;">{html.escape(info['summary'])}</p>

        <h3 style="margin:0 0 10px 0;font-size:15px;color:#111827;border-bottom:2px solid #e5e7eb;padding-bottom:6px;">Section 2: Affected Server</h3>
        <table width="100%" cellpadding="0" cellspacing="0" style="font-size:14px;margin-bottom:22px;">{render_html_rows(server_rows)}</table>

        <h3 style="margin:0 0 10px 0;font-size:15px;color:#111827;border-bottom:2px solid #e5e7eb;padding-bottom:6px;">Section 3: User Information</h3>
        <table width="100%" cellpadding="0" cellspacing="0" style="font-size:14px;margin-bottom:22px;">{render_html_rows(user_rows)}</table>

        <h3 style="margin:0 0 10px 0;font-size:15px;color:#111827;border-bottom:2px solid #e5e7eb;padding-bottom:6px;">Section 4: Activity Details</h3>
        <table width="100%" cellpadding="0" cellspacing="0" style="font-size:14px;margin-bottom:22px;background:#f9fafb;border:1px solid #e5e7eb;border-radius:6px;">{render_html_rows(activity_rows)}</table>

        <h3 style="margin:0 0 10px 0;font-size:15px;color:#111827;border-bottom:2px solid #e5e7eb;padding-bottom:6px;">Section 5: Security Explanation</h3>
        <div style="background-color:{bg_tint};border-left:4px solid {badge_color};padding:14px 16px;font-size:14px;line-height:1.6;margin-bottom:22px;">{html.escape(info['explanation'])}</div>

        <h3 style="margin:0 0 10px 0;font-size:15px;color:#111827;border-bottom:2px solid #e5e7eb;padding-bottom:6px;">Section 6: Recommended Actions</h3>
        <ol style="margin:0;padding-left:20px;font-size:14px;line-height:1.6;">{actions_html}</ol>
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
    msg.attach(MIMEText(plain_body, "plain", "utf-8"))
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=10) as s:
        s.sendmail(SENDER_EMAIL, RECIPIENT_EMAILS, msg.as_string())


if __name__ == "__main__":
    main()
EOF

sed -i "s|__SENDER_EMAIL__|${SMTP_USERNAME}|g" /var/ossec/integrations/custom-html-email.py
sed -i "s|__RECIPIENT_EMAIL__|${ALERT_RECIPIENT_EMAIL}|g" /var/ossec/integrations/custom-html-email.py

chown root:wazuh /var/ossec/integrations/custom-html-email.py
chmod 750 /var/ossec/integrations/custom-html-email.py
mkdir -p /var/ossec/tmp
chown root:wazuh /var/ossec/tmp
chmod 770 /var/ossec/tmp

/var/ossec/framework/python/bin/python3 -m py_compile /var/ossec/integrations/custom-html-email.py
/var/ossec/bin/wazuh-analysisd -t && systemctl restart wazuh-manager
```

* **Validation:**
  ```bash
  ls -la /var/ossec/integrations/custom-html-email.py
  systemctl status wazuh-manager --no-pager
  ```

---

## 19. Wazuh Dashboard Multi-User Management

### 19.1 Understanding the 5 Account Types in a Wazuh Environment

Do not confuse Linux server accounts with Wazuh web accounts:

| Account Type | Where It Lives | Purpose | Example |
| :--- | :--- | :--- | :--- |
| **1. Linux Server Users** | `/etc/passwd` on RHEL servers | OS login via SSH, SFTP, or TigerVNC | `ec2-user`, `user1`, `user2`, `user3`, `user4` |
| **2. Wazuh Agents** | `/var/ossec/etc/client.keys` | Server-to-Server encrypted telemetry link | `vnc-server` (Agent ID `001`) |
| **3. Wazuh Indexer Internal Users** | OpenSearch Security Plugin | Authenticates human users logging into the Wazuh Dashboard web UI | `admin`, `jakir` |
| **4. Wazuh Server API Users** | `wazuh-apid` RBAC database | Authenticates Dashboard-to-Manager API requests (e.g., active response, rule edits) | `wazuh-wui` (service account) + mapped RBAC roles |
| **5. Wazuh Dashboard Users** | Backed by Wazuh Indexer Security | The web session resulting from Indexer + API RBAC mapping | Team member web logins |

---

## 20. Role-Based Access Management (RBAC)

To allow multiple team members to access the Wazuh Dashboard without sharing the default `admin` password, create dedicated internal users and map them to three privilege tiers:

| Role Tier | Placeholder Username | Indexer Role | Wazuh API Role | Capabilities |
| :--- | :--- | :--- | :--- | :--- |
| **Tier 1: Administrator** | `admin` | `all_access` | `administrator` | Full access to rules, decoders, agent management, and user administration |
| **Tier 2: Security Analyst** | `jakir` | `readall_and_monitor` + `kibana_user` | `readonly` + `agents_read` | Investigate alerts, Threat Hunting, FIM, dashboards, and reports; **cannot** edit rules or delete agents |
| **Tier 3: Read-Only Viewer** | `viewuser` | `readall` + `kibana_read_only` | `readonly` | View dashboards and security events only; cannot modify saved objects or settings |

### 20.1 Step-by-Step Procedure to Create Team Accounts in Wazuh Dashboard

1. **Create the Internal User in OpenSearch Security:**
   * Log in to `https://<WAZUH_MANAGER_IP>` as `admin`.
   * Open the top-left menu ($\equiv$) -> **Indexer Management** -> **Security** -> **Internal users** -> **Create internal user**.
   * Create `admin`, `jakir`, and `viewuser` with strong passwords (minimum 12 characters).
2. **Map Indexer Backend Roles:**
   * Go to **Indexer Management** -> **Security** -> **Roles**.
   * Select `all_access` -> **Mapped users** -> **Manage mapping** -> Add `admin`.
   * Select `kibana_user` and `readall_and_monitor` -> **Manage mapping** -> Add `jakir` and `viewuser`.
3. **Map Wazuh Server API RBAC Permissions (Critical Step in Wazuh 4.14):**
   * Open the top-left menu ($\equiv$) -> **Server Management** -> **Security** -> **Roles mapping** -> **Create Role mapping**.
   * **Mapping 1 (Admins):**
     * **Role mapping name:** `Team_Administrators`
     * **Roles:** `administrator`
     * **Internal users:** `admin`
   * **Mapping 2 (Analysts & Viewers — Read-Only Server Config):**
     * **Role mapping name:** `Team_Security_Analysts_ReadOnly`
     * **Roles:** `readonly`
     * **Internal users:** `jakir`, `viewuser`
   * Click **Save role mapping**.
4. **How to Disable or Remove an Employee Account (Offboarding):**
   * Navigate to **Server Management** -> **Security** -> **Roles mapping** and remove the user from the mapping.
   * Navigate to **Indexer Management** -> **Security** -> **Internal users**, select the user, and click **Delete**.
5. **Auditing Dashboard Administrative Activity:**
   * All Wazuh Server API calls (including rule edits and role changes) are logged in `/var/ossec/logs/api.log` on `ec2-user` with the authenticated username and source IP.

---

## 21. Testing and Validation

Execute these real-world manual tests from an authorized Linux testing machine against `<SERVER_PRIVATE_IP>` (`172.31.15.62`).

*(Note on `ec2-user` Password Testing: If `ec2-user` does not have a Linux password set, set a temporary strong password with `sudo passwd ec2-user` on `vnc-server` before running Test 1, or test with `-o PreferredAuthentications=password -o PubkeyAuthentication=no`.)*

### 21.1 Test Execution & Verification Commands

#### Test 1: 5 Invalid SSH Passwords for `ec2-user` (Medium Brute-Force)
* **Location:** Testing Machine
* **Command:**
  ```bash
  for i in {1..5}; do
    ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1 ec2-user@<SERVER_PRIVATE_IP>
  done
  ```
* **Verification on Wazuh Manager:**
  ```bash
  grep '"id":"100601"' /var/ossec/logs/alerts/alerts.json | grep "ec2-user" | tail -n 1
  tail -n 15 /var/log/maillog
  ```

#### Test 2: 5 Invalid SSH Passwords for `user1` (Medium Brute-Force)
* **Location:** Testing Machine
* **Command:**
  ```bash
  for i in {1..5}; do
    ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1 user1@<SERVER_PRIVATE_IP>
  done
  ```

#### Test 3: 5 Invalid SSH Passwords for `user3` (`sftp-denied` Account)
* **Location:** Testing Machine
* **Command:**
  ```bash
  for i in {1..5}; do
    ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1 user3@<SERVER_PRIVATE_IP>
  done
  ```

#### Test 4: 10 Invalid SSH Passwords Within 5 Minutes (High Escalation)
* **Location:** Testing Machine
* **Command:** Run 5 additional failed attempts for `user1` within 5 minutes of Test 2 (total 10 failed attempts).
* **Verification on Wazuh Manager:**
  ```bash
  grep '"id":"100611"' /var/ossec/logs/alerts/alerts.json | tail -n 1
  ```

#### Test 5: Successful SSH Login (`ec2-user`)
* **Location:** Testing Machine
* **Command:** `ssh ec2-user@<SERVER_PRIVATE_IP>` (Authenticate and `exit`).

#### Test 6, 7 & 8: SFTP Login & File Upload by `user1`, File Download by `user2`
* **Location:** Testing Machine
* **Command:**
  ```bash
  echo "Semiconductor verification test" > wafer_map.gds
  sftp user1@<SERVER_PRIVATE_IP>
  # Inside sftp>:
  cd files
  put wafer_map.gds
  exit

  # Copy file into user2's directory on vnc-server or upload and download as user2:
  sftp user2@<SERVER_PRIVATE_IP>
  cd files
  put wafer_map.gds
  get wafer_map.gds wafer_map_downloaded.gds
  exit
  ```
* **Verification on Wazuh Manager:**
  ```bash
  grep '"id":"100507"' /var/ossec/logs/alerts/alerts.json | tail -n 5
  ```

#### Test 9: Unauthorized SFTP Attempt by `user3` (`sftp-denied`)
* **Location:** Testing Machine
* **Command:**
  ```bash
  sftp user3@<SERVER_PRIVATE_IP>
  # Enter user3's valid password -> Immediately rejected by /usr/sbin/nologin
  ```
* **Verification on Wazuh Manager:**
  ```bash
  grep '"id":"100505"' /var/ossec/logs/alerts/alerts.json | tail -n 1
  ```

#### Test 10 & 11: TigerVNC Authentication Failure & Success as `user1` (`:1` / Port `5901`)
* **Location:** Testing Machine (using `vncviewer <SERVER_PRIVATE_IP>:5901`)
* **Action:** First enter an invalid VNC password (triggers Rule `100510`), then connect with `user1`'s valid VNC password (triggers Rule `100509`).
* **Verification on Wazuh Manager:**
  ```bash
  grep -E '"id":"100509"|"id":"100510"' /var/ossec/logs/alerts/alerts.json | tail -n 2
  ```

#### Test 12 & 13: Create a New Linux User (`staff01`) and Perform SSH/SFTP Without Editing Wazuh
* **Location:** Wazuh Agent (`vnc-server`)
* **Command:**
  ```bash
  useradd -m -s /bin/bash staff01
  passwd staff01
  /usr/local/sbin/setup-sftp-chroot-user.sh staff01
  ```
* **Location:** Testing Machine
* **Command:** Connect via `sftp staff01@<SERVER_PRIVATE_IP>`, `cd files`, and `put wafer_map.gds`.
* **Verification on Wazuh Manager:** Confirm Rule `100507` fires with `dstuser: staff01` and sends 1 HTML email identifying `staff01`.

---

## 22. Troubleshooting Reference

| Symptom | Diagnostic Command | Root Cause & Resolution |
| :--- | :--- | :--- |
| **1. Wazuh agent disconnected** | `/var/ossec/bin/agent_control -i 001` | Verify TCP ports `1514` and `1515` are open in AWS Security Group and `firewalld` on `<WAZUH_MANAGER_IP>`. |
| **2. SFTP upload/download events missing for chrooted users** | `grep "/srv/sftp" /proc/mounts` (on Agent) | Chrooted `internal-sftp` requires `/srv/sftp/<user>/dev/log` bind-mounted to `/run/systemd/journal/dev-log`. Run `/usr/local/sbin/setup-sftp-chroot-user.sh <user>`. |
| **3. SFTP user reported as `ec2-user`** | Check `/var/ossec/integrations/custom-html-email.py` | Ensure `custom-html-email.py` does not fall back to `syscheck.audit.user.name` (`auid`) on SFTP events and uses the PID session cache (`Step 18.1`). |
| **4. Brute-force rule not triggering on `ec2-user` or `user3`** | `tail -n 20 /var/log/secure` (on Agent) | Ensure `PasswordAuthentication yes` is active for the user and use `ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no` when testing. |
| **5. Medium brute-force triggers, High does not** | Check rule order in `ssh_and_network_rules.xml` | Rule `100611` (`frequency="10"`) must appear **above** Rule `100601` (`frequency="5"`), and `100601` must include `authentication_failed` in its `<group>` list. |
| **6. Duplicate emails for the same incident** | `grep "<integration>" /var/ossec/etc/ossec.conf` | Verify `<email_notification>no</email_notification>` is set, only one `<integration>` block exists, and `journald` is removed from Agent `ossec.conf` when `/var/log/secure` is collected. |
| **7. Postfix authentication failure (`535 5.7.8`)** | `tail -n 30 /var/log/maillog` | Regenerate a 16-character Google App Password, update `/etc/postfix/sasl_passwd`, run `postmap /etc/postfix/sasl_passwd`, and `systemctl restart postfix`. |

---

## 23. Backup and Rollback Procedures

To roll back to the pre-change state at any time, restore from the timestamped backup directory created in **Section 4**:

```bash
# On Wazuh Manager:
cp -a /root/wazuh_manager_backup_<TIMESTAMP>/ossec.conf /var/ossec/etc/ossec.conf
cp -a /root/wazuh_manager_backup_<TIMESTAMP>/decoders/* /var/ossec/etc/decoders/
cp -a /root/wazuh_manager_backup_<TIMESTAMP>/rules/* /var/ossec/etc/rules/
cp -a /root/wazuh_manager_backup_<TIMESTAMP>/integrations/* /var/ossec/integrations/
/var/ossec/bin/wazuh-analysisd -t && systemctl restart wazuh-manager

# On Wazuh Agent:
cp -a /root/wazuh_agent_backup_<TIMESTAMP>/sshd_config /etc/ssh/sshd_config
cp -a /root/wazuh_agent_backup_<TIMESTAMP>/sshd_config.d/* /etc/ssh/sshd_config.d/
sshd -t && systemctl reload sshd
cp -a /root/wazuh_agent_backup_<TIMESTAMP>/ossec.conf /var/ossec/etc/ossec.conf
systemctl restart wazuh-agent
```

---

## 24. Employee Onboarding and Offboarding Procedures

### 24.1 Onboarding a New Engineering User (Linux + SFTP + TigerVNC)

* **Location:** Wazuh Agent (`vnc-server`)
* **Execution user:** `root`

```bash
NEW_USER="<LINUX_USERNAME>"
VNC_DISP="<VNC_DISPLAY_NUMBER>"   # e.g., :5

# 1. Create Linux user and set password
useradd -m -s /bin/bash "$NEW_USER"
chmod 700 "/home/${NEW_USER}"
passwd "$NEW_USER"

# 2A. If user is allowed SFTP access:
/usr/local/sbin/setup-sftp-chroot-user.sh "$NEW_USER"

# 2B. OR if user is DENIED SFTP access (VNC-only):
# usermod -aG sftp-denied "$NEW_USER"

# 3. Configure TigerVNC display (if VNC access is required):
echo "${VNC_DISP}=${NEW_USER}" >> /etc/tigervnc/vncserver.users
su - "$NEW_USER" -c "vncpasswd"
systemctl daemon-reload
systemctl enable --now "vncserver@${VNC_DISP}.service"
systemctl restart wazuh-agent
```

### 24.2 Offboarding an Employee

* **Location:** Wazuh Agent (`vnc-server`)
* **Execution user:** `root`

```bash
OLD_USER="<LINUX_USERNAME>"
VNC_DISP="<VNC_DISPLAY_NUMBER>"   # e.g., :5

# 1. Stop VNC session and lock Linux account
systemctl disable --now "vncserver@${VNC_DISP}.service" 2>/dev/null || true
sed -i "/=${OLD_USER}$/d" /etc/tigervnc/vncserver.users
usermod -L "$OLD_USER"
pkill -KILL -u "$OLD_USER" || true

# 2. Unmount chroot /dev/log socket if present
if grep -q "/srv/sftp/${OLD_USER}/dev/log" /proc/mounts; then
    umount "/srv/sftp/${OLD_USER}/dev/log"
fi
sed -i "\|/srv/sftp/${OLD_USER}/dev/log|d" /etc/fstab
```
