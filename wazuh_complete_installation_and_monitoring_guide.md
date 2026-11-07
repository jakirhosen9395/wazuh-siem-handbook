# Wazuh v4.14.9 Complete Installation, Security Monitoring & HTML Email Alert Runbook

This master engineering runbook provides the complete, sequential procedure to build a production **Wazuh v4.14.9** security monitoring platform from scratch on empty **Red Hat Enterprise Linux (RHEL) 9.8** servers. Every command, full configuration file, certificate setup, custom decoder, detection rule, and HTML email integration script is included in exact chronological execution order.

---

## 1. Architecture, Prerequisites & Implementation Audit

### 1.1 Environment Topology & Placeholders

Replace the following placeholders with your actual environment values when executing commands:

| Placeholder | Description | Reference Value from Deployment |
| :--- | :--- | :--- |
| `<WAZUH_SERVER_IP>` | Private IPv4 of the Wazuh All-in-One Server (`wazuh-server`) | `11.11.2.165` |
| `<AGENT_SERVER_IP>` | Private IPv4 of the Monitored Linux Agent (`vnc-server`) | `11.11.3.185` |
| `<TEST_CLIENT_IP_1>` | First IPv4 used for SSH/SFTP testing | `11.11.2.50` |
| `<TEST_CLIENT_IP_2>` | Second IPv4 used for multi-IP & brute-force testing | `11.11.2.165` |
| `<SENDER_EMAIL_ADDRESS>` | Gmail / SMTP account used by Postfix to send alerts | `your-sender@gmail.com` |
| `<RECIPIENT_EMAIL_ADDRESS>` | Destination email address receiving security alerts | `your-recipient@gmail.com` |
| `<GMAIL_16_CHAR_APP_PASSWORD>` | 16-character Google App Password for Postfix SASL | `xxxxxxxxxxxxxxxx` |
| `<WAZUH_ADMIN_PASSWORD>` | Auto-generated password for Wazuh Dashboard `admin` user | *(Extracted from `wazuh-passwords.txt`)* |

```text
+-----------------------------------------------------------------------------------+
| MONITORED LINUX AGENT: vnc-server (11.11.3.185) - RHEL 9.8 (x86_64)         |
|                                                                                   |
|  +-----------------------+   +-----------------------+   +---------------------+  |
|  | /var/log/secure       |   | /var/log/audit/       |   | Command & FIM       |  |
|  | (SSHD, PAM, SFTP)     |   | audit.log (execve,    |   | Collectors (ss,     |  |
|  | LogLevel VERBOSE      |   | passwd, sshd, vnc)    |   | whodata="/etc,...") |  |
|  +-----------+-----------+   +-----------+-----------+   +----------+----------+  |
|              |                           |                          |             |
|              +---------------------------+--------------------------+             |
|                                          |                                        |
|                                          v                                        |
|                     wazuh-logcollector / wazuh-syscheckd / syscollector           |
|                                          |                                        |
|                              wazuh-agentd (1514/TCP TLS)                          |
+------------------------------------------|----------------------------------------+
                                           |
                                           v
+-----------------------------------------------------------------------------------+
| WAZUH ALL-IN-ONE SERVER: wazuh-server (11.11.2.165) - RHEL 9.8 (x86_64)     |
|                                                                                   |
|  wazuh-remoted (1514/TCP) ---> wazuh-analysisd                                    |
|                                  |-- Built-in Decoders (sshd, pam, auditd)        |
|                                  |-- Custom Decoders (sftp_decoders.xml)          |
|                                  |-- Custom SFTP/VNC Rules (100501-100506)        |
|                                  |-- Custom SSH/Net Rules (100601-100623)         |
|                                          |                                        |
|                         +----------------+----------------+                       |
|                         |                                 |                       |
|                         v                                 v                       |
|        /var/ossec/logs/alerts/alerts.json        wazuh-integratord                |
|                         |                                 |                       |
|                         v                                 v                       |
|              Filebeat -> wazuh-indexer        custom-html-email.py                |
|               (OpenSearch 2.19.6:9200)                    |                       |
|                         |                                 v                       |
|            wazuh-dashboard (443/TCP)          Postfix Relay (smtp.gmail.com:587)  |
+-----------------------------------------------------------------------------------+
```

### 1.2 Hardware & Storage Requirements

| Server Role | OS | vCPU | RAM & Swap | Root Disk (`/`) | Why This Spec Is Mandatory |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Wazuh All-in-One Server** (`wazuh-server`) | RHEL 9.8 (`x86_64`) | 4 vCPUs (Intel Xeon Platinum 8124M) | 8 GiB RAM (`7421 MB` usable) + **4 GiB Swap** | **100 GB GP3 EBS** (`99G` on `/dev/nvme0n1p4`) | Unpacking `wazuh-dashboard` (`286 MB` RPM / `960 MB` installed) and `wazuh-indexer` (`836 MB` RPM) fails on small disks without swap; OpenSearch locks indices at 85% disk usage. |
| **Wazuh Agent Server** (`vnc-server`) | RHEL 9.8 (`x86_64`) | 2–4 vCPUs | 4–8 GiB RAM | **50 GB+ GP3 EBS** | Stores local `/var/log/audit/audit.log`, `/var/log/secure`, and VNC/engineering workspaces. |

### 1.3 Network & Firewall Port Matrix

| Port | Protocol | Source | Destination | Component / Service | Purpose |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **443** | TCP | Admin Workstations | `11.11.2.165` | `wazuh-dashboard` | Wazuh Web UI (HTTPS) |
| **1514** | TCP | `11.11.3.185` | `11.11.2.165` | `wazuh-remoted` | Encrypted agent event forwarding |
| **1515** | TCP | `11.11.3.185` | `11.11.2.165` | `wazuh-authd` | Agent enrollment and key exchange |
| **55000** | TCP | `127.0.0.1` / Admins | `11.11.2.165` | `wazuh-apid` | Wazuh Manager RESTful API |
| **9200** | TCP | `127.0.0.1` | `127.0.0.1` | `wazuh-indexer` | OpenSearch REST API (Localhost only) |
| **587** | TCP | `11.11.2.165` | `smtp.gmail.com` | `postfix` | Outbound STARTTLS email alert delivery |
| **22** | TCP | Authorized Subnets | Both Servers | `sshd` | SSH and `internal-sftp` access |

### 1.4 Audit of Completed vs. Pending Configurations

| Category | Configuration Item | Status |
| :--- | :--- | :--- |
| **OS & Disk Prep** | RHEL 9.8 kernel upgrade (`5.14.0-687.66.1.el9_8.x86_64`), 100 GB root disk, 4 GB Swap, `vm.max_map_count=262144`, DNF timeouts, `fontconfig`/`lsof`/`libcap` dependencies | **Completed** |
| **Wazuh Server** | Wazuh v4.14.9 All-in-One (`wazuh-indexer`, `wazuh-manager`, `filebeat`, `wazuh-dashboard`) installed, verified, and yum repo disabled | **Completed** |
| **Wazuh Agent** | Wazuh Agent v4.14.9 installed via RPM on `vnc-server`, registered (`ID: 001`), 1-second `loop_timeout` configured | **Completed** |
| **Auditd & FIM** | Kernel `auditd` `execve` tracking (`audit-wazuh-c`), `/etc/passwd` watches (`user-modify`), `/etc/tigervnc` watch, and `<syscheck>` `whodata="yes"` | **Completed** |
| **SFTP Monitoring** | OpenSSH `LogLevel VERBOSE`, `internal-sftp -f AUTHPRIV -l INFO`, `sftp-allowed` & `sftp-denied` groups, PCRE2 decoders (`sftp_decoders.xml`), Rules `100501–100506` | **Completed** |
| **Postfix SMTP** | Postfix SASL auth to `[smtp.gmail.com]:587` with Google App Password | **Completed (Needs IPv4 tuning in Step 16)** |
| **SSH & Net Rules** | Custom SSH Brute-Force (`5 in 5m`), Multi-IP (`<different_srcip />`), Username Enumeration, Root Login, Compromise After Brute-Force, and Listening Port Diff Rules (`100601–100623`) | **To Be Implemented (Steps 11, 12, 15)** |
| **HTML Email Engine** | Custom Python HTML Email Integration (`/var/ossec/integrations/custom-html-email.py`) and removal of duplicate plain-text email triggers | **To Be Implemented (Steps 14, 17, 18)** |

---

## 2. Phase 1: Wazuh Server OS Preparation (From Empty Server)

### Step 1: Update All OS Packages, Kernel, and Reboot
* **Server:** Wazuh Manager (`wazuh-server` — `11.11.2.165`, RHEL 9.8)
* **Files Modified:** System packages and Linux kernel

#### Commands:
```bash
sudo dnf clean all
sudo dnf makecache
sudo dnf upgrade -y
sudo dnf needs-restarting -r || sudo reboot
```

#### Validation:
```bash
uname -r
cat /etc/redhat-release
```

#### Expected Result:
The server boots into the latest RHEL 9.8 kernel (`5.14.0-687.66.1.el9_8.x86_64`) and outputs `Red Hat Enterprise Linux release 9.8 (Plow)`.

---

### Step 2: Configure System Hostname, 4 GB Swap File, and Kernel Virtual Memory Parameters
* **Server:** Wazuh Manager (`wazuh-server` — `11.11.2.165`, RHEL 9.8)
* **Files Modified:** `/etc/hostname`, `/swapfile`, `/etc/fstab`, `/etc/sysctl.d/99-wazuh.conf`

#### Configuration (`/etc/sysctl.d/99-wazuh.conf`):
```ini
vm.max_map_count=262144
vm.swappiness=10
```

#### Commands:
```bash
# 1. Set system hostname
sudo hostnamectl set-hostname wazuh-server

# 2. Create and enable a persistent 4 GB Swap file
sudo fallocate -l 4G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
grep -q '/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab

# 3. Apply kernel virtual memory map count required by Wazuh Indexer (OpenSearch)
cat << 'EOF' | sudo tee /etc/sysctl.d/99-wazuh.conf
vm.max_map_count=262144
vm.swappiness=10
EOF

sudo sysctl --system
```

#### Validation:
```bash
free -m
sysctl vm.max_map_count vm.swappiness
```

#### Expected Result:
`free -m` shows `4095` MB under `Swap: total`, and `sysctl` outputs `vm.max_map_count = 262144` and `vm.swappiness = 10`.

---

### Step 3: Verify and Expand Root Filesystem Capacity (`100 GB`)
* **Server:** Wazuh Manager (`wazuh-server` — `11.11.2.165`, RHEL 9.8)
* **Device Modified:** `/dev/nvme0n1p4` (`/`)

#### Commands:
```bash
sudo dnf install -y cloud-utils-growpart
sudo growpart /dev/nvme0n1 4 || true
sudo xfs_growfs /
```

#### Validation:
```bash
df -h /
```

#### Expected Result:
`df -h /` displays `/dev/nvme0n1p4` with `Size: 99G` and `Avail: ~92G`.

---

### Step 4: Configure DNF Resiliency, Pre-Install OS Dependencies, and Open Firewall Ports
* **Server:** Wazuh Manager (`wazuh-server` — `11.11.2.165`, RHEL 9.8)
* **File Modified:** `/etc/dnf/dnf.conf`

#### Commands:
```bash
# 1. Increase DNF timeout and retries so large Wazuh RPM downloads never abort
grep -q '^timeout=' /etc/dnf/dnf.conf || echo -e "timeout=300\nretries=10\nminrate=1000" | sudo tee -a /etc/dnf/dnf.conf

# 2. Pre-install required utilities and shared libraries required by wazuh-dashboard and wazuh-indexer
sudo dnf install -y curl tar coreutils gnupg2 lsof libcap fontconfig nss openssl-libs policycoreutils-python-utils

# 3. Open required Wazuh ports in firewalld (if active)
if systemctl is-active --quiet firewalld; then
    sudo firewall-cmd --permanent --add-port={443/tcp,1514/tcp,1515/tcp,55000/tcp}
    sudo firewall-cmd --reload
fi
```

#### Validation:
```bash
tail -n 5 /etc/dnf/dnf.conf
rpm -q curl tar coreutils gnupg2 lsof libcap fontconfig nss openssl-libs policycoreutils-python-utils
```

#### Expected Result:
All 10 RPM packages return their installed RHEL 9 versions without error, and `timeout=300` is present in `/etc/dnf/dnf.conf`.

---

## 3. Phase 2: Complete Wazuh v4.14.9 All-in-One Installation

Below are both the **Automated Installation Assistant (Method A)** used in our deployment and the **Step-by-Step Component Installation (Method B)** showing exact repository creation, certificate generation, Indexer, Manager, Filebeat, and Dashboard installation.

### Step 5A: Install Wazuh All-in-One Using the Official Installation Assistant (Method A — Primary)
* **Server:** Wazuh Manager (`wazuh-server` — `11.11.2.165`, RHEL 9.8)
* **Files Created:**
  * `/etc/yum.repos.d/wazuh.repo`
  * `~/wazuh-install-files.tar` (contains root-ca, node certificates, and `wazuh-passwords.txt`)
  * `/etc/wazuh-indexer/opensearch.yml`
  * `/var/ossec/etc/ossec.conf`
  * `/etc/filebeat/filebeat.yml`
  * `/etc/wazuh-dashboard/opensearch_dashboards.yml`

#### Commands:
```bash
cd ~
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
sudo bash ./wazuh-install.sh -a -i -v
```

What this command executes sequentially:
1. Configures `/etc/yum.repos.d/wazuh.repo` with GPG key `https://packages.wazuh.com/key/GPG-KEY-WAZUH`.
2. Generates X.509 Root CA, Admin, Indexer, Filebeat (`wazuh-server`), and Dashboard certificates bound to `127.0.0.1` and archives them in `wazuh-install-files.tar`.
3. Installs `wazuh-indexer-4.14.9-1.x86_64` (`836 MB`), copies certificates to `/etc/wazuh-indexer/certs/`, starts `wazuh-indexer.service`, and runs `indexer-security-init.sh` against `127.0.0.1:9200`.
4. Installs `wazuh-manager-4.14.9-1.x86_64` (`548 MB`), configures vulnerability detection, and starts `wazuh-manager.service`.
5. Installs `filebeat-7.10.2-2.x86_64` (`21 MB`), downloads the Wazuh alerts template and Filebeat module, configures `/etc/filebeat/certs/`, and starts `filebeat.service`.
6. Installs `wazuh-dashboard-4.14.9-1.x86_64` (`286 MB`), configures `/etc/wazuh-dashboard/certs/`, starts `wazuh-dashboard.service`, randomizes internal cluster passwords, and prints the `admin` login summary.

#### Validation:
```bash
sudo tar -O -xvf ~/wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt | grep -A 2 "indexer_username: 'admin'"
```

#### Expected Result:
Terminal prints `INFO: Installation finished.` along with the `admin` user and `<WAZUH_ADMIN_PASSWORD>`.

---

### Step 5B: Step-by-Step Component Installation Reference (Method B — If Installing Each Component Individually)
* **Server:** Wazuh Manager (`wazuh-server` — `11.11.2.165`, RHEL 9.8)
* **Files Created:** `config.yml`, `/etc/yum.repos.d/wazuh.repo`, `/etc/wazuh-indexer/opensearch.yml`, `/etc/filebeat/filebeat.yml`, `/etc/wazuh-dashboard/opensearch_dashboards.yml`

*(Execute Method B only if you choose not to run the single `-a` flag in Step 5A.)*

#### Configuration (`config.yml` for Certificate Generation):
```yaml
nodes:
  indexer:
    - name: node-1
      ip: "127.0.0.1"
  server:
    - name: wazuh-1
      ip: "127.0.0.1"
  dashboard:
    - name: dashboard
      ip: "127.0.0.1"
```

#### Configuration (`/etc/yum.repos.d/wazuh.repo`):
```ini
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
```

#### Commands (Individual Component Execution):
```bash
# 1. Import GPG Key and configure Wazuh Repository
sudo rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
cat << 'EOF' | sudo tee /etc/yum.repos.d/wazuh.repo
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
EOF

# 2. Generate X.509 Certificates for Indexer, Server, and Dashboard
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
cat << 'EOF' > config.yml
nodes:
  indexer:
    - name: node-1
      ip: "127.0.0.1"
  server:
    - name: wazuh-1
      ip: "127.0.0.1"
  dashboard:
    - name: dashboard
      ip: "127.0.0.1"
EOF
sudo bash ./wazuh-install.sh --generate-config-files

# 3. Install and Initialize Wazuh Indexer
sudo bash ./wazuh-install.sh --wazuh-indexer node-1 -i
sudo bash ./wazuh-install.sh --start-cluster

# 4. Install Wazuh Server (wazuh-manager + filebeat)
sudo bash ./wazuh-install.sh --wazuh-server wazuh-1 -i

# 5. Install Wazuh Dashboard
sudo bash ./wazuh-install.sh --wazuh-dashboard dashboard -i
```

---

### Step 6: Verify All Wazuh Services, Back Up Certificates/Passwords, and Lock the Repository
* **Server:** Wazuh Manager (`wazuh-server` — `11.11.2.165`, RHEL 9.8)
* **Files Modified:** `/root/wazuh-install-files-backup.tar`, `/etc/yum.repos.d/wazuh.repo`

#### Commands:
```bash
# 1. Back up the generated certificates and passwords archive to /root
sudo cp ~/wazuh-install-files.tar /root/wazuh-install-files-backup.tar
sudo chmod 600 /root/wazuh-install-files-backup.tar

# 2. Disable the Wazuh repository so routine 'dnf upgrade' runs do not break version parity
sudo sed -i "s/^enabled=1/enabled=0/" /etc/yum.repos.d/wazuh.repo

# 3. Verify all 4 services are active and enabled
sudo systemctl status wazuh-indexer wazuh-manager filebeat wazuh-dashboard --no-pager
```

#### Validation:
```bash
grep "^enabled=" /etc/yum.repos.d/wazuh.repo
sudo curl -k -u admin:<WAZUH_ADMIN_PASSWORD> https://127.0.0.1:9200/_cluster/health?pretty
```

#### Expected Result:
`wazuh.repo` shows `enabled=0`, all 4 services show `Active: active (running)`, and the OpenSearch cluster health returns `"status" : "green"`.

---

## 4. Phase 3: Complete Wazuh Agent Installation & Registration (`vnc-server`)

### Step 7: Prepare the Agent OS and Verify Network Connectivity to the Wazuh Manager
* **Server:** Wazuh Agent (`vnc-server` — `11.11.3.185`, RHEL 9.8)
* **Files Modified:** System packages

#### Commands:
```bash
# 1. Update packages on the agent server
sudo dnf clean all
sudo dnf makecache
sudo dnf upgrade -y

# 2. Ensure auditd is installed and active
sudo dnf install -y audit curl coreutils
sudo systemctl enable --now auditd

# 3. Verify TCP connectivity to Wazuh Manager on ports 1514 and 1515
timeout 3 bash -c "</dev/tcp/11.11.2.165/1514 && echo 'Port 1514 (Remoted) Open'"
timeout 3 bash -c "</dev/tcp/11.11.2.165/1515 && echo 'Port 1515 (Authd) Open'"
```

#### Validation:
```bash
systemctl is-active auditd
```

#### Expected Result:
Both port checks print `Open`, and `auditd` returns `active`.

---

### Step 8: Install, Enroll, and Start the Wazuh v4.14.9 Agent
* **Server:** Wazuh Agent (`vnc-server` — `11.11.3.185`, RHEL 9.8)
* **Files Created/Modified:** `/var/ossec/etc/ossec.conf`, `/var/ossec/etc/client.keys`, `/var/ossec/etc/local_internal_options.conf`

#### Commands:
```bash
# 1. Import the official Wazuh GPG signing key
sudo rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH

# 2. Download and install the Wazuh Agent 4.14.9 RPM with auto-enrollment variables
curl -o wazuh-agent-4.14.9-1.x86_64.rpm https://packages.wazuh.com/4.x/yum/wazuh-agent-4.14.9-1.x86_64.rpm && \
sudo WAZUH_MANAGER='11.11.2.165' WAZUH_AGENT_NAME='vnc-server' rpm -ihv wazuh-agent-4.14.9-1.x86_64.rpm

# 3. Clean up the downloaded RPM file
rm -f wazuh-agent-4.14.9-1.x86_64.rpm

# 4. Configure 1-second logcollector polling loop for real-time event forwarding
grep -q "logcollector.loop_timeout" /var/ossec/etc/local_internal_options.conf || \
echo "logcollector.loop_timeout=1" | sudo tee -a /var/ossec/etc/local_internal_options.conf

# 5. Enable and start wazuh-agent
sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-agent
```

#### Validation (Execute on Agent):
```bash
sudo systemctl status wazuh-agent --no-pager
sudo grep -E "Valid key received|Connected to the server" /var/ossec/logs/ossec.log
```

#### Validation (Execute on Wazuh Manager):
```bash
sudo /var/ossec/bin/agent_control -l
```

#### Expected Result:
Agent `ossec.log` shows `Valid key received` and `Connected to the server ([11.11.2.165]:1514/tcp)`, and `agent_control -l` on the Manager lists `ID: 001, Name: vnc-server, IP: any, Active`.

---

## 5. Phase 4: Complete SSH, SFTP, Command, FIM, and Network Monitoring Setup

### Step 9: Configure OpenSSH (`sshd`) for Verbose Authentication Logging & SFTP Access Control
* **Server:** Wazuh Agent (`vnc-server` — `11.11.3.185`, RHEL 9.8)
* **Files Modified:** `/etc/ssh/sshd_config`, `/etc/ssh/sshd_config.d/50-sftp-monitoring.conf`

#### Configuration (`/etc/ssh/sshd_config.d/50-sftp-monitoring.conf`):
```sshconfig
LogLevel VERBOSE
SyslogFacility AUTHPRIV
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
```

#### Commands:
```bash
# 1. Create the SFTP access control Linux groups
sudo groupadd -f sftp-allowed
sudo groupadd -f sftp-denied

# 2. Comment out default Subsystem sftp line in /etc/ssh/sshd_config to prevent duplicate subsystem errors
sudo sed -i 's/^Subsystem[[:space:]]\+sftp/#Subsystem sftp/' /etc/ssh/sshd_config

# 3. Create the drop-in SSH & SFTP monitoring configuration
sudo tee /etc/ssh/sshd_config.d/50-sftp-monitoring.conf << 'EOF'
LogLevel VERBOSE
SyslogFacility AUTHPRIV
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

# 4. Validate sshd syntax and reload service
sudo sshd -t && sudo systemctl reload sshd
```

#### Validation:
```bash
sudo sshd -T | grep -E "loglevel|syslogfacility|subsystem"
```

#### Expected Result:
Outputs `loglevel VERBOSE`, `syslogfacility AUTHPRIV`, and `subsystem sftp internal-sftp -f AUTHPRIV -l INFO`.

---

### Step 10: Configure Kernel `auditd` Rules on Both Agent and Manager
* **Server:** Execute on **Wazuh Agent (`vnc-server`)** AND **Wazuh Manager (`wazuh-server`)**
* **File Created:** `/etc/audit/rules.d/wazuh-full-monitoring.rules`

#### Configuration (`/etc/audit/rules.d/wazuh-full-monitoring.rules`):
```text
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

## 3. Track SSHD configuration modifications
-w /etc/ssh/sshd_config -p wa -k sshd-config-modify
-w /etc/ssh/sshd_config.d/ -p wa -k sshd-config-modify

## 4. Track Network & Firewall configuration changes
-w /etc/firewalld/ -p wa -k network-config-modify
-w /etc/NetworkManager/system-connections/ -p wa -k network-config-modify
-w /etc/hosts -p wa -k network-config-modify
-w /etc/resolv.conf -p wa -k network-config-modify
```

#### Commands (Run on `vnc-server` and `wazuh-server`):
```bash
# 1. Remove any older duplicate audit rule files and pre-create watched directories so augenrules never fails
sudo rm -f /etc/audit/rules.d/wazuh-command-audit.rules
sudo mkdir -p /etc/tigervnc /etc/firewalld /etc/NetworkManager/system-connections /etc/ssh/sshd_config.d

# 2. Write the complete audit rules file
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

## 3. Track SSHD configuration modifications
-w /etc/ssh/sshd_config -p wa -k sshd-config-modify
-w /etc/ssh/sshd_config.d/ -p wa -k sshd-config-modify

## 4. Track Network & Firewall configuration changes
-w /etc/firewalld/ -p wa -k network-config-modify
-w /etc/NetworkManager/system-connections/ -p wa -k network-config-modify
-w /etc/hosts -p wa -k network-config-modify
-w /etc/resolv.conf -p wa -k network-config-modify
EOF

# 3. Load rules into the kernel dynamically (Note: RHEL 9 refuses systemctl restart auditd by design)
sudo augenrules --load

# 4. If firewalld is active, enable logging of rejected/dropped inbound packets
if systemctl is-active --quiet firewalld; then
    sudo firewall-cmd --set-log-denied=unicast
fi
```

#### Validation:
```bash
sudo auditctl -l
```

#### Expected Result:
`sudo auditctl -l` outputs all 13 loaded rules (`audit-wazuh-c`, `user-modify`, `vnc-config-modify`, `sshd-config-modify`, `network-config-modify`) with zero `Rule exists` or missing-file errors.

---

### Step 11: Configure Complete Wazuh Agent `ossec.conf` (SSH, SFTP, Auditd, Whodata FIM & Port Monitoring)
* **Server:** Wazuh Agent (`vnc-server` — `11.11.3.185`, RHEL 9.8)
* **File Modified:** `/var/ossec/etc/ossec.conf`

#### Complete Configuration (`/var/ossec/etc/ossec.conf` on Agent):
```xml
<ossec_config>
  <client>
    <server>
      <address>11.11.2.165</address>
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

    <!-- Real-time kernel whodata monitoring for critical system, SSH, and user directories -->
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
    <command>ss -tulpnH | awk '{print $1, $5}' | sort -u</command>
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
```

#### Commands:
```bash
sudo cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak

sudo tee /var/ossec/etc/ossec.conf << 'EOF'
<ossec_config>
  <client>
    <server>
      <address>11.11.2.165</address>
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
    <command>ss -tulpnH | awk '{print $1, $5}' | sort -u</command>
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
sudo /var/ossec/bin/wazuh-syscheckd -t
sudo grep -E "Analyzing file|Whodata|active listening sockets" /var/ossec/logs/ossec.log | tail -n 15
```

#### Expected Result:
`wazuh-syscheckd -t` returns 0 errors, and `ossec.log` confirms `/var/log/secure`, `/var/log/audit/audit.log`, `/var/log/messages`, `active listening sockets`, and the real-time `Whodata` engine are running.

---

### Step 12: Configure Complete Wazuh Manager `ossec.conf` (With HTML Email Integration Enabled)
* **Server:** Wazuh Manager (`wazuh-server` — `11.11.2.165`, RHEL 9.8)
* **File Modified:** `/var/ossec/etc/ossec.conf`

*(Note: In this complete Manager configuration, `<email_notification>no</email_notification>` is set so legacy plain-text emails from `wazuh-maild` do not duplicate the rich HTML incident emails sent by `<integration><name>custom-html-email.py</name></integration>`.)*

#### Complete Configuration (`/var/ossec/etc/ossec.conf` on Manager):
```xml
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>no</logall>
    <logall_json>no</logall_json>
    <email_notification>no</email_notification>
    <smtp_server>localhost</smtp_server>
    <email_from>devops.jakir@gmail.com</email_from>
    <email_to>hiddenclue0@gmail.com</email_to>
    <email_maxperhour>1000</email_maxperhour>
    <email_log_source>alerts.log</email_log_source>
    <agents_disconnection_time>15m</agents_disconnection_time>
    <agents_disconnection_alert_time>0</agents_disconnection_alert_time>
    <update_check>yes</update_check>
  </global>

  <alerts>
    <log_alert_level>3</log_alert_level>
    <email_alert_level>12</email_alert_level>
  </alerts>

  <logging>
    <log_format>plain</log_format>
  </logging>

  <remote>
    <connection>secure</connection>
    <port>1514</port>
    <protocol>tcp</protocol>
    <queue_size>131072</queue_size>
  </remote>

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
    <rootkit_files>etc/rootcheck/rootkit_files.txt</rootkit_files>
    <rootkit_trojans>etc/rootcheck/rootkit_trojans.txt</rootkit_trojans>
    <skip_nfs>yes</skip_nfs>
    <ignore>/var/lib/containerd</ignore>
    <ignore>/var/lib/docker/overlay2</ignore>
  </rootcheck>

  <wodle name="cis-cat">
    <disabled>yes</disabled>
    <timeout>1800</timeout>
    <interval>1d</interval>
    <scan-on-start>yes</scan-on-start>
    <java_path>wodles/java</java_path>
    <ciscat_path>wodles/ciscat</ciscat_path>
  </wodle>

  <wodle name="osquery">
    <disabled>yes</disabled>
    <run_daemon>yes</run_daemon>
    <log_path>/var/log/osquery/osqueryd.results.log</log_path>
    <config_path>/etc/osquery/osquery.conf</config_path>
    <add_labels>yes</add_labels>
  </wodle>

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

  <vulnerability-detection>
    <enabled>yes</enabled>
    <index-status>yes</index-status>
    <feed-update-interval>60m</feed-update-interval>
  </vulnerability-detection>

  <indexer>
    <enabled>yes</enabled>
    <hosts>
      <host>https://127.0.0.1:9200</host>
    </hosts>
    <ssl>
      <certificate_authorities>
        <ca>/etc/filebeat/certs/root-ca.pem</ca>
      </certificate_authorities>
      <certificate>/etc/filebeat/certs/wazuh-server.pem</certificate>
      <key>/etc/filebeat/certs/wazuh-server-key.pem</key>
    </ssl>
  </indexer>

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

    <nodiff type="sregex">^/etc/ssl/private/|^/etc/pki/tls/private/</nodiff>
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

  <global>
    <white_list>127.0.0.1</white_list>
    <white_list>^localhost.localdomain$</white_list>
    <white_list>11.11.0.2</white_list>
  </global>

  <command>
    <name>disable-account</name>
    <executable>disable-account</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>restart-wazuh</name>
    <executable>restart-wazuh</executable>
  </command>

  <command>
    <name>firewall-drop</name>
    <executable>firewall-drop</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>host-deny</name>
    <executable>host-deny</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>route-null</name>
    <executable>route-null</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

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
    <command>ss -tulpnH | awk '{print $1, $5}' | sort -u</command>
    <alias>active listening sockets</alias>
    <frequency>60</frequency>
  </localfile>

  <localfile>
    <log_format>full_command</log_format>
    <command>last -n 20</command>
    <frequency>360</frequency>
  </localfile>

  <ruleset>
    <decoder_dir>ruleset/decoders</decoder_dir>
    <rule_dir>ruleset/rules</rule_dir>
    <rule_exclude>0215-policy_rules.xml</rule_exclude>
    <list>etc/lists/audit-keys</list>
    <list>etc/lists/amazon/aws-eventnames</list>
    <list>etc/lists/security-eventchannel</list>
    <list>etc/lists/malicious-ioc/malware-hashes</list>
    <list>etc/lists/malicious-ioc/malicious-ip</list>
    <list>etc/lists/malicious-ioc/malicious-domains</list>
    <decoder_dir>etc/decoders</decoder_dir>
    <rule_dir>etc/rules</rule_dir>
  </ruleset>

  <rule_test>
    <enabled>yes</enabled>
    <threads>1</threads>
    <max_sessions>64</max_sessions>
    <session_timeout>15m</session_timeout>
  </rule_test>

  <auth>
    <disabled>no</disabled>
    <port>1515</port>
    <use_source_ip>no</use_source_ip>
    <purge>yes</purge>
    <use_password>no</use_password>
    <ciphers>HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH</ciphers>
    <ssl_verify_host>no</ssl_verify_host>
    <ssl_manager_cert>etc/sslmanager.cert</ssl_manager_cert>
    <ssl_manager_key>etc/sslmanager.key</ssl_manager_key>
    <ssl_auto_negotiate>no</ssl_auto_negotiate>
  </auth>

  <cluster>
    <name>wazuh</name>
    <node_name>node01</node_name>
    <node_type>master</node_type>
    <key></key>
    <port>1516</port>
    <bind_addr>0.0.0.0</bind_addr>
    <nodes>
        <node>NODE_IP</node>
    </nodes>
    <hidden>no</hidden>
    <disabled>yes</disabled>
  </cluster>

  <!-- Custom HTML Email Notification Integration -->
  <integration>
    <name>custom-html-email.py</name>
    <group>sftp_alert,email_notify_alert,vnc_monitoring,</group>
    <alert_format>json</alert_format>
  </integration>
</ossec_config>

<ossec_config>
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
    <location>/var/ossec/logs/active-responses.log</location>
  </localfile>
</ossec_config>
```

#### Commands:
```bash
sudo cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.pre-master

sudo tee /var/ossec/etc/ossec.conf << 'EOF'
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>no</logall>
    <logall_json>no</logall_json>
    <email_notification>no</email_notification>
    <smtp_server>localhost</smtp_server>
    <email_from>devops.jakir@gmail.com</email_from>
    <email_to>hiddenclue0@gmail.com</email_to>
    <email_maxperhour>1000</email_maxperhour>
    <email_log_source>alerts.log</email_log_source>
    <agents_disconnection_time>15m</agents_disconnection_time>
    <agents_disconnection_alert_time>0</agents_disconnection_alert_time>
    <update_check>yes</update_check>
  </global>

  <alerts>
    <log_alert_level>3</log_alert_level>
    <email_alert_level>12</email_alert_level>
  </alerts>

  <logging>
    <log_format>plain</log_format>
  </logging>

  <remote>
    <connection>secure</connection>
    <port>1514</port>
    <protocol>tcp</protocol>
    <queue_size>131072</queue_size>
  </remote>

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
    <rootkit_files>etc/rootcheck/rootkit_files.txt</rootkit_files>
    <rootkit_trojans>etc/rootcheck/rootkit_trojans.txt</rootkit_trojans>
    <skip_nfs>yes</skip_nfs>
    <ignore>/var/lib/containerd</ignore>
    <ignore>/var/lib/docker/overlay2</ignore>
  </rootcheck>

  <wodle name="cis-cat">
    <disabled>yes</disabled>
    <timeout>1800</timeout>
    <interval>1d</interval>
    <scan-on-start>yes</scan-on-start>
    <java_path>wodles/java</java_path>
    <ciscat_path>wodles/ciscat</ciscat_path>
  </wodle>

  <wodle name="osquery">
    <disabled>yes</disabled>
    <run_daemon>yes</run_daemon>
    <log_path>/var/log/osquery/osqueryd.results.log</log_path>
    <config_path>/etc/osquery/osquery.conf</config_path>
    <add_labels>yes</add_labels>
  </wodle>

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

  <vulnerability-detection>
    <enabled>yes</enabled>
    <index-status>yes</index-status>
    <feed-update-interval>60m</feed-update-interval>
  </vulnerability-detection>

  <indexer>
    <enabled>yes</enabled>
    <hosts>
      <host>https://127.0.0.1:9200</host>
    </hosts>
    <ssl>
      <certificate_authorities>
        <ca>/etc/filebeat/certs/root-ca.pem</ca>
      </certificate_authorities>
      <certificate>/etc/filebeat/certs/wazuh-server.pem</certificate>
      <key>/etc/filebeat/certs/wazuh-server-key.pem</key>
    </ssl>
  </indexer>

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

    <nodiff type="sregex">^/etc/ssl/private/|^/etc/pki/tls/private/</nodiff>
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

  <global>
    <white_list>127.0.0.1</white_list>
    <white_list>^localhost.localdomain$</white_list>
    <white_list>11.11.0.2</white_list>
  </global>

  <command>
    <name>disable-account</name>
    <executable>disable-account</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>restart-wazuh</name>
    <executable>restart-wazuh</executable>
  </command>

  <command>
    <name>firewall-drop</name>
    <executable>firewall-drop</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>host-deny</name>
    <executable>host-deny</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>route-null</name>
    <executable>route-null</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

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
    <command>ss -tulpnH | awk '{print $1, $5}' | sort -u</command>
    <alias>active listening sockets</alias>
    <frequency>60</frequency>
  </localfile>

  <localfile>
    <log_format>full_command</log_format>
    <command>last -n 20</command>
    <frequency>360</frequency>
  </localfile>

  <ruleset>
    <decoder_dir>ruleset/decoders</decoder_dir>
    <rule_dir>ruleset/rules</rule_dir>
    <rule_exclude>0215-policy_rules.xml</rule_exclude>
    <list>etc/lists/audit-keys</list>
    <list>etc/lists/amazon/aws-eventnames</list>
    <list>etc/lists/security-eventchannel</list>
    <list>etc/lists/malicious-ioc/malware-hashes</list>
    <list>etc/lists/malicious-ioc/malicious-ip</list>
    <list>etc/lists/malicious-ioc/malicious-domains</list>
    <decoder_dir>etc/decoders</decoder_dir>
    <rule_dir>etc/rules</rule_dir>
  </ruleset>

  <rule_test>
    <enabled>yes</enabled>
    <threads>1</threads>
    <max_sessions>64</max_sessions>
    <session_timeout>15m</session_timeout>
  </rule_test>

  <auth>
    <disabled>no</disabled>
    <port>1515</port>
    <use_source_ip>no</use_source_ip>
    <purge>yes</purge>
    <use_password>no</use_password>
    <ciphers>HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH</ciphers>
    <ssl_verify_host>no</ssl_verify_host>
    <ssl_manager_cert>etc/sslmanager.cert</ssl_manager_cert>
    <ssl_manager_key>etc/sslmanager.key</ssl_manager_key>
    <ssl_auto_negotiate>no</ssl_auto_negotiate>
  </auth>

  <cluster>
    <name>wazuh</name>
    <node_name>node01</node_name>
    <node_type>master</node_type>
    <key></key>
    <port>1516</port>
    <bind_addr>0.0.0.0</bind_addr>
    <nodes>
        <node>NODE_IP</node>
    </nodes>
    <hidden>no</hidden>
    <disabled>yes</disabled>
  </cluster>

  <integration>
    <name>custom-html-email.py</name>
    <group>sftp_alert,email_notify_alert,vnc_monitoring,</group>
    <alert_format>json</alert_format>
  </integration>
</ossec_config>

<ossec_config>
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
    <location>/var/ossec/logs/active-responses.log</location>
  </localfile>
</ossec_config>
EOF

sudo chown root:wazuh /var/ossec/etc/ossec.conf
sudo chmod 660 /var/ossec/etc/ossec.conf
```

#### Validation:
```bash
sudo /var/ossec/bin/wazuh-analysisd -t
```

#### Expected Result:
`wazuh-analysisd -t` returns `0` with no XML errors.

---

## 6. Phase 5: Custom Decoders & Security Detection Rules

### Step 13: Create Custom PCRE2 SFTP Decoders (`sftp_decoders.xml`)
* **Server:** Wazuh Manager (`wazuh-server` — `11.11.2.165`, RHEL 9.8)
* **File Created:** `/var/ossec/etc/decoders/sftp_decoders.xml`

#### Configuration (`/var/ossec/etc/decoders/sftp_decoders.xml`):
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

#### Commands:
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

#### Validation:
```bash
sudo /var/ossec/bin/wazuh-analysisd -t
```

#### Expected Result:
`wazuh-analysisd -t` compiles the PCRE2 regular expressions cleanly with zero syntax errors.

---

### Step 14: Create Custom SFTP & TigerVNC Monitoring Rules (`sftp_and_vnc_rules.xml`)
* **Server:** Wazuh Manager (`wazuh-server` — `11.11.2.165`, RHEL 9.8)
* **File Created:** `/var/ossec/etc/rules/sftp_and_vnc_rules.xml`

#### Configuration (`/var/ossec/etc/rules/sftp_and_vnc_rules.xml`):
```xml
<group name="sftp_monitoring,">

  <!-- Rule 100501: SFTP Session Opened -->
  <rule id="100501" level="10">
    <match>session opened for local user</match>
    <description>SFTP: Session opened by user $(dstuser) from IP $(srcip)</description>
    <group>authentication_success,sftp_alert,</group>
  </rule>

  <!-- Rule 100502: SFTP File Uploaded / Written -->
  <rule id="100502" level="12">
    <match>flags WRITE|flags CREATE|flags TRUNCATE|flags APPEND</match>
    <description>SFTP File Upload/Write Detected: File "$(file)" opened with $(extra_data)</description>
    <group>syscheck,sftp_alert,</group>
  </rule>

  <!-- Rule 100503: SFTP File Downloaded / Read -->
  <rule id="100503" level="10">
    <match>flags READ</match>
    <description>SFTP File Download/Read Detected: File "$(file)" read via SFTP</description>
    <group>sftp_alert,</group>
  </rule>

  <!-- Rule 100504: SFTP File Deleted, Renamed, or Permission Changed -->
  <rule id="100504" level="12">
    <regex>remove name "|rmdir name "|rename old "|setstat name "</regex>
    <description>SFTP File Delete/Rename/Permission change detected</description>
    <group>syscheck,sftp_alert,</group>
  </rule>

  <!-- Rule 100505: Blocked SFTP User (sftp-denied group triggered ForceCommand /usr/bin/false) -->
  <rule id="100505" level="12">
    <if_group>sshd</if_group>
    <match>Forced command '/usr/bin/false'|forced-command (config) '/usr/bin/false'|subsystem request for sftp failed</match>
    <description>SFTP Access Blocked: Unauthorized user attempted SFTP access</description>
    <group>authentication_failed,sftp_alert,</group>
  </rule>

  <!-- Rule 100506: TigerVNC Configuration Modified -->
  <rule id="100506" level="10">
    <if_sid>80700</if_sid>
    <field name="audit.key">vnc-config-modify</field>
    <description>VNC Configuration Modified by user $(audit.auid)</description>
    <group>vnc_monitoring,</group>
  </rule>

</group>
```

#### Commands:
```bash
sudo tee /var/ossec/etc/rules/sftp_and_vnc_rules.xml << 'EOF'
<group name="sftp_monitoring,">

  <rule id="100501" level="10">
    <match>session opened for local user</match>
    <description>SFTP: Session opened by user $(dstuser) from IP $(srcip)</description>
    <group>authentication_success,sftp_alert,</group>
  </rule>

  <rule id="100502" level="12">
    <match>flags WRITE|flags CREATE|flags TRUNCATE|flags APPEND</match>
    <description>SFTP File Upload/Write Detected: File "$(file)" opened with $(extra_data)</description>
    <group>syscheck,sftp_alert,</group>
  </rule>

  <rule id="100503" level="10">
    <match>flags READ</match>
    <description>SFTP File Download/Read Detected: File "$(file)" read via SFTP</description>
    <group>sftp_alert,</group>
  </rule>

  <rule id="100504" level="12">
    <regex>remove name "|rmdir name "|rename old "|setstat name "</regex>
    <description>SFTP File Delete/Rename/Permission change detected</description>
    <group>syscheck,sftp_alert,</group>
  </rule>

  <rule id="100505" level="12">
    <if_group>sshd</if_group>
    <match>Forced command '/usr/bin/false'|forced-command (config) '/usr/bin/false'|subsystem request for sftp failed</match>
    <description>SFTP Access Blocked: Unauthorized user attempted SFTP access</description>
    <group>authentication_failed,sftp_alert,</group>
  </rule>

  <rule id="100506" level="10">
    <if_sid>80700</if_sid>
    <field name="audit.key">vnc-config-modify</field>
    <description>VNC Configuration Modified by user $(audit.auid)</description>
    <group>vnc_monitoring,</group>
  </rule>

</group>
EOF

sudo chown wazuh:wazuh /var/ossec/etc/rules/sftp_and_vnc_rules.xml
sudo chmod 660 /var/ossec/etc/rules/sftp_and_vnc_rules.xml
```

#### Validation:
```bash
sudo /var/ossec/bin/wazuh-analysisd -t
```

#### Expected Result:
`wazuh-analysisd -t` returns `0` with no errors.

---

### Step 15: Create Custom SSH Threat Detection & Network Rules (`ssh_and_network_rules.xml`)
* **Server:** Wazuh Manager (`wazuh-server` — `11.11.2.165`, RHEL 9.8)
* **File Created:** `/var/ossec/etc/rules/ssh_and_network_rules.xml`

#### Complete Rule Specification Matrix

| Rule ID | Rule Name / Scenario | Level | Frequency / Timeframe | Correlation Tags / Decoder | Log Source |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **100601** | **Rule 1a:** SSH Brute-Force Attack by Source IP (5 failures in 5 mins) | `12` | `frequency="5"`, `timeframe="300"` | `<if_matched_group>authentication_failed</if_matched_group>`, `<same_source_ip />` | `/var/log/secure` (`sshd`) |
| **100602** | **Rule 1b:** SSH Brute-Force Attack by Target Username (5 failures in 5 mins) | `12` | `frequency="5"`, `timeframe="300"` | `<if_matched_group>authentication_failed</if_matched_group>`, `<same_user />` | `/var/log/secure` (`sshd`) |
| **100603** | **Rule 2:** Same Username Logged In From 2 Different IPs Within 5 Minutes | `11` | `frequency="2"`, `timeframe="300"` | `<if_matched_sid>5715</if_matched_sid>`, `<same_user />`, `<different_srcip />` | `/var/log/secure` (`sshd`) |
| **100604** | **Rule 3:** Multiple Distinct Usernames Targeted From 1 IP (Enumeration) | `12` | `frequency="4"`, `timeframe="300"` | `<if_matched_group>authentication_failed</if_matched_group>`, `<same_source_ip />`, `<different_user />` | `/var/log/secure` (`sshd`) |
| **100605** | **Rule 4:** Successful SSH Login Following Repeated Failures (Compromise Indicator) | `14` | `timeframe="300"` after Rule `100601` | `<if_sid>5715</if_sid>`, `<if_matched_sid>100601</if_matched_sid>`, `<same_source_ip />` | `/var/log/secure` (`sshd`) |
| **100606** | **Rule 5a:** Direct Root SSH Login Succeeded | `12` | Immediate (`1` event) | `<if_sid>5715</if_sid>`, `<user>^root$</user>` | `/var/log/secure` (`sshd`) |
| **100607** | **Rule 5b:** Direct Root SSH Login Attempt Failed | `10` | Immediate (`1` event) | `<if_group>authentication_failed</if_group>`, `<user>^root$</user>` | `/var/log/secure` (`sshd`) |
| **100608** | **Rule 6a:** Suspicious SSH Login From Non-Private External IP | `11` | Immediate (`1` event) | `<if_sid>5715</if_sid>`, `<srcip negate="yes">^11\.|^10\.|^192\.168\.|^172\.|^127\.</srcip>` | `/var/log/secure` (`sshd`) |
| **100609** | **Rule 6b:** SSH Login Outside Maintenance Window (`22:00 - 06:00`) | `10` | Immediate (`1` event) | `<if_sid>5715</if_sid>`, `<time>22:00 - 06:00</time>` | `/var/log/secure` (`sshd`) |
| **100610** | **Rule 6c:** SSH Daemon Configuration Modified (`sshd-config-modify`) | `12` | Immediate (`1` event) | `<if_sid>80700</if_sid>`, `<field name="audit.key">sshd-config-modify</field>` | `/var/log/audit/audit.log` |
| **100620** | **Rule 7a:** Change in Active Listening TCP/UDP Ports (`ss -tulpnH`) | `10` | Immediate on diff | `<if_sid>530</if_sid>`, `<match>^ossec: output: 'active listening sockets'</match>`, `<check_diff />` | Agent `full_command` |
| **100621** | **Rule 7b:** Firewall or Network Configuration Modified (`network-config-modify`) | `11` | Immediate (`1` event) | `<if_sid>80700</if_sid>`, `<field name="audit.key">network-config-modify</field>` | `/var/log/audit/audit.log` |
| **100622** | **Rule 7c:** Firewall Blocked Inbound Connection (`FINAL_REJECT` / `HOST_REJECT`) | `7` | Immediate (`1` event) | `<match>FINAL_REJECT:|HOST_REJECT:</match>` | `/var/log/messages` |
| **100623** | **Rule 7d:** Repeated Blocked Inbound Connections / Port Scan (5 in 2 mins) | `11` | `frequency="5"`, `timeframe="120"` | `<if_matched_sid>100622</if_matched_sid>`, `<same_source_ip />` | `/var/log/messages` |

#### Configuration (`/var/ossec/etc/rules/ssh_and_network_rules.xml`):
```xml
<group name="ssh_security_monitoring,network_security_monitoring,">

  <rule id="100601" level="12" frequency="5" timeframe="300">
    <if_matched_group>authentication_failed</if_matched_group>
    <same_source_ip />
    <description>SSH Brute-Force Attack Detected: 5 failed login attempts within 5 minutes from IP $(srcip) (last target user: $(dstuser))</description>
    <mitre>
      <id>T1110.001</id>
    </mitre>
    <group>authentication_failures,ssh_brute_force,email_notify_alert,</group>
  </rule>

  <rule id="100602" level="12" frequency="5" timeframe="300">
    <if_matched_group>authentication_failed</if_matched_group>
    <same_user />
    <description>SSH Account Brute-Force Detected: 5 failed login attempts within 5 minutes targeting user $(dstuser) (from IP $(srcip))</description>
    <mitre>
      <id>T1110.001</id>
    </mitre>
    <group>authentication_failures,ssh_brute_force,email_notify_alert,</group>
  </rule>

  <rule id="100603" level="11" frequency="2" timeframe="300">
    <if_matched_sid>5715</if_matched_sid>
    <same_user />
    <different_srcip />
    <description>Suspicious Concurrent SSH Access: User $(dstuser) logged in from multiple different IP addresses within 5 minutes (latest IP: $(srcip))</description>
    <mitre>
      <id>T1078</id>
    </mitre>
    <group>authentication_success,ssh_multi_ip,email_notify_alert,</group>
  </rule>

  <rule id="100604" level="12" frequency="4" timeframe="300">
    <if_matched_group>authentication_failed</if_matched_group>
    <same_source_ip />
    <different_user />
    <description>SSH Username Enumeration / Spraying Detected: Source IP $(srcip) failed authentication against multiple distinct usernames within 5 minutes (latest user: $(dstuser))</description>
    <mitre>
      <id>T1110.003</id>
    </mitre>
    <group>authentication_failures,ssh_enumeration,email_notify_alert,</group>
  </rule>

  <rule id="100605" level="14" timeframe="300">
    <if_sid>5715</if_sid>
    <if_matched_sid>100601</if_matched_sid>
    <same_source_ip />
    <description>CRITICAL: Successful SSH login by user $(dstuser) from IP $(srcip) immediately following an SSH brute-force attack</description>
    <mitre>
      <id>T1110</id>
      <id>T1078</id>
    </mitre>
    <group>authentication_success,ssh_compromise_indicator,email_notify_alert,</group>
  </rule>

  <rule id="100606" level="12">
    <if_sid>5715</if_sid>
    <user>^root$</user>
    <description>Direct Root SSH Login Succeeded from IP $(srcip) port $(srcport)</description>
    <mitre>
      <id>T1078.003</id>
    </mitre>
    <group>authentication_success,root_ssh_login,email_notify_alert,</group>
  </rule>

  <rule id="100607" level="10">
    <if_group>authentication_failed</if_group>
    <user>^root$</user>
    <description>Direct Root SSH Login Attempt Failed from IP $(srcip)</description>
    <mitre>
      <id>T1078.003</id>
    </mitre>
    <group>authentication_failed,root_ssh_login,</group>
  </rule>

  <rule id="100608" level="11">
    <if_sid>5715</if_sid>
    <!-- Use standard Wazuh syntax for negating IP networks (! means NOT) -->
    <srcip>!10.0.0.0/8</srcip>
    <srcip>!11.0.0.0/8</srcip>
    <srcip>!172.16.0.0/12</srcip>
    <srcip>!192.168.0.0/16</srcip>
    <srcip>!127.0.0.0/8</srcip>
    <description>Suspicious External SSH Login: User $(dstuser) authenticated from non-private external IP $(srcip)</description>
    <mitre>
      <id>T1078</id>
    </mitre>
    <group>authentication_success,external_ssh_login,email_notify_alert,</group>
  </rule>

  <rule id="100609" level="10">
    <if_sid>5715</if_sid>
    <time>22:00 - 06:00</time>
    <description>Off-Hours SSH Login Detected: User $(dstuser) logged in from IP $(srcip) outside normal maintenance hours (22:00-06:00)</description>
    <group>authentication_success,off_hours_ssh,email_notify_alert,</group>
  </rule>

  <rule id="100610" level="12">
    <if_sid>80700</if_sid>
    <field name="audit.key">sshd-config-modify</field>
    <description>SSH Daemon Configuration Modified: $(audit.file.name) modified by user AUID $(audit.auid)</description>
    <mitre>
      <id>T1098</id>
    </mitre>
    <group>sshd_config_change,email_notify_alert,</group>
  </rule>

  <rule id="100620" level="10">
    <if_sid>530</if_sid>
    <match>^ossec: output: 'active listening sockets'</match>
    <check_diff />
    <description>Network Port Change Detected: Active TCP/UDP listening sockets changed on server</description>
    <mitre>
      <id>T1049</id>
    </mitre>
    <group>network_port_change,email_notify_alert,</group>
  </rule>

  <rule id="100621" level="11">
    <if_sid>80700</if_sid>
    <field name="audit.key">network-config-modify</field>
    <description>Firewall or Network Configuration Modified: $(audit.file.name) changed by user AUID $(audit.auid)</description>
    <mitre>
      <id>T1562.004</id>
    </mitre>
    <group>firewall_config_change,email_notify_alert,</group>
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
    <group>firewall_drop,port_scan_detected,email_notify_alert,</group>
  </rule>

</group>
```

#### Commands:
```bash
sudo tee /var/ossec/etc/rules/ssh_and_network_rules.xml << 'EOF'
<group name="ssh_security_monitoring,network_security_monitoring,">

  <rule id="100601" level="12" frequency="5" timeframe="300">
    <if_matched_group>authentication_failed</if_matched_group>
    <same_source_ip />
    <description>SSH Brute-Force Attack Detected: 5 failed login attempts within 5 minutes from IP $(srcip) (last target user: $(dstuser))</description>
    <mitre>
      <id>T1110.001</id>
    </mitre>
    <group>authentication_failures,ssh_brute_force,email_notify_alert,</group>
  </rule>

  <rule id="100602" level="12" frequency="5" timeframe="300">
    <if_matched_group>authentication_failed</if_matched_group>
    <same_user />
    <description>SSH Account Brute-Force Detected: 5 failed login attempts within 5 minutes targeting user $(dstuser) (from IP $(srcip))</description>
    <mitre>
      <id>T1110.001</id>
    </mitre>
    <group>authentication_failures,ssh_brute_force,email_notify_alert,</group>
  </rule>

  <rule id="100603" level="11" frequency="2" timeframe="300">
    <if_matched_sid>5715</if_matched_sid>
    <same_user />
    <different_srcip />
    <description>Suspicious Concurrent SSH Access: User $(dstuser) logged in from multiple different IP addresses within 5 minutes (latest IP: $(srcip))</description>
    <mitre>
      <id>T1078</id>
    </mitre>
    <group>authentication_success,ssh_multi_ip,email_notify_alert,</group>
  </rule>

  <rule id="100604" level="12" frequency="4" timeframe="300">
    <if_matched_group>authentication_failed</if_matched_group>
    <same_source_ip />
    <different_user />
    <description>SSH Username Enumeration / Spraying Detected: Source IP $(srcip) failed authentication against multiple distinct usernames within 5 minutes (latest user: $(dstuser))</description>
    <mitre>
      <id>T1110.003</id>
    </mitre>
    <group>authentication_failures,ssh_enumeration,email_notify_alert,</group>
  </rule>

  <rule id="100605" level="14" timeframe="300">
    <if_sid>5715</if_sid>
    <if_matched_sid>100601</if_matched_sid>
    <same_source_ip />
    <description>CRITICAL: Successful SSH login by user $(dstuser) from IP $(srcip) immediately following an SSH brute-force attack</description>
    <mitre>
      <id>T1110</id>
      <id>T1078</id>
    </mitre>
    <group>authentication_success,ssh_compromise_indicator,email_notify_alert,</group>
  </rule>

  <rule id="100606" level="12">
    <if_sid>5715</if_sid>
    <user>^root$</user>
    <description>Direct Root SSH Login Succeeded from IP $(srcip) port $(srcport)</description>
    <mitre>
      <id>T1078.003</id>
    </mitre>
    <group>authentication_success,root_ssh_login,email_notify_alert,</group>
  </rule>

  <rule id="100607" level="10">
    <if_group>authentication_failed</if_group>
    <user>^root$</user>
    <description>Direct Root SSH Login Attempt Failed from IP $(srcip)</description>
    <mitre>
      <id>T1078.003</id>
    </mitre>
    <group>authentication_failed,root_ssh_login,</group>
  </rule>

  <rule id="100608" level="11">
    <if_sid>5715</if_sid>
    <!-- Use standard Wazuh syntax for negating IP networks (! means NOT) -->
    <srcip>!10.0.0.0/8</srcip>
    <srcip>!11.0.0.0/8</srcip>
    <srcip>!172.16.0.0/12</srcip>
    <srcip>!192.168.0.0/16</srcip>
    <srcip>!127.0.0.0/8</srcip>
    <description>Suspicious External SSH Login: User $(dstuser) authenticated from non-private external IP $(srcip)</description>
    <mitre>
      <id>T1078</id>
    </mitre>
    <group>authentication_success,external_ssh_login,email_notify_alert,</group>
  </rule>

  <rule id="100609" level="10">
    <if_sid>5715</if_sid>
    <time>22:00 - 06:00</time>
    <description>Off-Hours SSH Login Detected: User $(dstuser) logged in from IP $(srcip) outside normal maintenance hours (22:00-06:00)</description>
    <group>authentication_success,off_hours_ssh,email_notify_alert,</group>
  </rule>

  <rule id="100610" level="12">
    <if_sid>80700</if_sid>
    <field name="audit.key">sshd-config-modify</field>
    <description>SSH Daemon Configuration Modified: $(audit.file.name) modified by user AUID $(audit.auid)</description>
    <mitre>
      <id>T1098</id>
    </mitre>
    <group>sshd_config_change,email_notify_alert,</group>
  </rule>

  <rule id="100620" level="10">
    <if_sid>530</if_sid>
    <match>^ossec: output: 'active listening sockets'</match>
    <check_diff />
    <description>Network Port Change Detected: Active TCP/UDP listening sockets changed on server</description>
    <mitre>
      <id>T1049</id>
    </mitre>
    <group>network_port_change,email_notify_alert,</group>
  </rule>

  <rule id="100621" level="11">
    <if_sid>80700</if_sid>
    <field name="audit.key">network-config-modify</field>
    <description>Firewall or Network Configuration Modified: $(audit.file.name) changed by user AUID $(audit.auid)</description>
    <mitre>
      <id>T1562.004</id>
    </mitre>
    <group>firewall_config_change,email_notify_alert,</group>
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
    <group>firewall_drop,port_scan_detected,email_notify_alert,</group>
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

## 7. Phase 6: Postfix SMTP Relay & Executive HTML Email Notification System

### Step 16: Install and Configure Postfix Gmail STARTTLS Relay
* **Server:** Wazuh Manager (`wazuh-server` — `11.11.2.165`, RHEL 9.8)
* **Files Modified:** `/etc/postfix/sasl_passwd`, `/etc/postfix/main.cf`

#### Configuration (`/etc/postfix/sasl_passwd`):
```text
[smtp.gmail.com]:587 devops.jakir@gmail.com:<GMAIL_16_CHAR_APP_PASSWORD>
```

#### Configuration (Appended to `/etc/postfix/main.cf`):
```ini
inet_protocols = ipv4
relayhost = [smtp.gmail.com]:587
smtp_use_tls = yes
smtp_sasl_auth_enable = yes
smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd
smtp_sasl_security_options = noanonymous
smtp_tls_security_level = encrypt
smtp_tls_cafile = /etc/ssl/certs/ca-bundle.crt
```

#### Commands:
```bash
# 1. Install Postfix, SASL authentication modules, and s-nail mail utility
sudo dnf install -y postfix cyrus-sasl cyrus-sasl-plain s-nail
sudo systemctl enable --now postfix

# 2. Create and hash the SASL password map
sudo tee /etc/postfix/sasl_passwd << 'EOF'
[smtp.gmail.com]:587 devops.jakir@gmail.com:<GMAIL_16_CHAR_APP_PASSWORD>
EOF
sudo chmod 600 /etc/postfix/sasl_passwd
sudo postmap /etc/postfix/sasl_passwd

# 3. Comment out default smtp_tls_security_level=may and force IPv4 to eliminate Gmail IPv6 timeouts
sudo sed -i 's/^smtp_tls_security_level = may/#smtp_tls_security_level = may/' /etc/postfix/main.cf
sudo postconf -e "inet_protocols = ipv4"

# 4. Append Gmail STARTTLS relay configuration if not already present
grep -q "relayhost = \[smtp.gmail.com\]:587" /etc/postfix/main.cf || sudo tee -a /etc/postfix/main.cf << 'EOF'

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

#### Validation:
```bash
echo "Postfix SMTP Relay Verification from Wazuh Server" | mail -s "Wazuh Postfix Relay Test" hiddenclue0@gmail.com
sleep 3
sudo tail -n 15 /var/log/maillog
```

#### Expected Result:
`/var/log/maillog` shows `relay=smtp.gmail.com[...]:587, ..., status=sent (250 2.0.0 OK ...)` with no `Network is unreachable` IPv6 warnings.

---

### Step 17: Create the Custom Python HTML Email Integration Script (`custom-html-email.py`)
* **Server:** Wazuh Manager (`wazuh-server` — `11.11.2.165`, RHEL 9.8)
* **File Created:** `/var/ossec/integrations/custom-html-email.py`

#### Complete Script (`/var/ossec/integrations/custom-html-email.py`):
```python
#!/var/ossec/framework/python/bin/python3
# -*- coding: utf-8 -*-
"""
Wazuh Custom HTML Security Alert Email Integration
Formats Wazuh JSON alerts into a standardized 7-section HTML + Plain-Text incident email
and delivers via local Postfix SMTP relay (127.0.0.1:25).
"""

import sys
import json
import smtplib
import html
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

SMTP_SERVER = "127.0.0.1"
SMTP_PORT = 25
SENDER_EMAIL = "devops.jakir@gmail.com"
RECIPIENT_EMAILS = ["hiddenclue0@gmail.com"]


def get_severity_info(level):
    if level >= 13:
        return "CRITICAL", "CRITICAL PRIORITY", "#b91c1c", "#fef2f2"
    elif level >= 11:
        return "HIGH", "HIGH PRIORITY", "#c2410c", "#fff7ed"
    elif level >= 7:
        return "MEDIUM", "MEDIUM PRIORITY", "#b45309", "#fffbeb"
    else:
        return "LOW", "LOW PRIORITY", "#1d4ed8", "#eff6ff"


def build_guidance(rule_id, groups, srcip, dstuser, file_path):
    rule_id_str = str(rule_id)

    if rule_id_str in ("100601", "100602"):
        what_happened = (
            f"An external or internal host ({srcip}) attempted to access the SSH service on this server "
            f"targeting user '{dstuser}' using repeated incorrect passwords. Five failed authentication "
            f"attempts were detected within five minutes. This activity may indicate an SSH brute-force attack."
        )
        actions = [
            f"Verify whether the source IP address ({srcip}) is authorized.",
            f"Check whether the targeted username ('{dstuser}') belongs to an active employee.",
            "Review recent successful login events to confirm no unauthorized access occurred.",
            "Contact the system administrator if the activity is unexpected.",
            f"Consider blocking the source IP ({srcip}) after investigation."
        ]
        category = "SSH Brute-Force Attack"
        condition = "5 failed SSH authentication attempts within 5 minutes (300 seconds)"

    elif rule_id_str == "100603":
        what_happened = (
            f"User account '{dstuser}' received successful SSH login events from two different source IP "
            f"addresses (most recently {srcip}) within five minutes. While this can occur when an engineer "
            f"switches networks or VPNs, it requires investigation for credential sharing or unauthorized access."
        )
        actions = [
            f"Confirm with employee '{dstuser}' whether they connected from two different workstations or networks.",
            "Verify whether both source IP addresses belong to known corporate subnets.",
            f"Ensure engineers are not sharing the '{dstuser}' account credentials.",
            f"If the login from {srcip} is unauthorized, terminate active sessions and rotate the account password."
        ]
        category = "Suspicious Multi-IP SSH Access"
        condition = "Same username authenticated from 2 different source IPs within 5 minutes"

    elif rule_id_str == "100604":
        what_happened = (
            f"A single source IP address ({srcip}) attempted SSH authentication against multiple distinct "
            f"usernames (most recently '{dstuser}') within five minutes. This behavior indicates potential "
            f"username enumeration or password spraying."
        )
        actions = [
            f"Verify whether source IP {srcip} is an authorized scanner or administrator host.",
            "Check if any targeted usernames are default or inactive accounts.",
            f"Block {srcip} at the firewall or AWS Security Group if unauthorized."
        ]
        category = "SSH Username Enumeration"
        condition = "4 failed SSH authentication attempts against distinct usernames from 1 IP within 5 minutes"

    elif rule_id_str == "100605":
        what_happened = (
            f"CRITICAL ALERT: Source IP {srcip} achieved a successful SSH login into user '{dstuser}' "
            f"immediately following repeated failed authentication attempts. The account may be compromised."
        )
        actions = [
            f"Contact '{dstuser}' immediately to verify if they just logged in from {srcip}.",
            f"If unexpected, lock the user account ('sudo usermod -L {dstuser}') and terminate their SSH session.",
            "Review all executed commands in the Wazuh Dashboard (Rule 80792).",
            "Reset the user's password and SSH authorized_keys immediately."
        ]
        category = "Successful Login After Brute-Force"
        condition = "Successful SSH login (Rule 5715) within 5 minutes of brute-force alert (Rule 100601)"

    elif rule_id_str in ("100606", "100607"):
        what_happened = (
            f"A direct SSH login attempt using the privileged 'root' account was detected from IP {srcip}. "
            f"Direct root logins obscure individual administrator accountability."
        )
        actions = [
            f"Verify which administrator initiated the root SSH session from {srcip}.",
            "Instruct administrators to log in with personal accounts and use sudo.",
            "Set 'PermitRootLogin no' in /etc/ssh/sshd_config if direct root SSH is not required."
        ]
        category = "Root SSH Login Activity"
        condition = "Direct SSH login event targeting user 'root'"

    elif rule_id_str in ("100501", "100502", "100503", "100504", "100505"):
        what_happened = (
            f"An SFTP file transfer or restricted SFTP access attempt occurred involving user '{dstuser}' "
            f"(Target file: {file_path}). All SFTP file uploads, downloads, deletions, and blocked attempts "
            f"are tracked for intellectual property protection."
        )
        actions = [
            f"Verify whether user '{dstuser}' is authorized to transfer or modify '{file_path}'.",
            "If Rule 100505 triggered, an SFTP-restricted VNC user attempted to use SFTP and was blocked.",
            "Contact the engineering security team if unauthorized design files were transferred."
        ]
        category = "SFTP File Transfer & Access Control"
        condition = "SFTP session, file read/write/delete, or blocked group access attempt"

    else:
        what_happened = (
            "Wazuh detected a suspicious SSH, network port, or configuration change event on the monitored "
            "server. Please review the affected server and technical details below."
        )
        actions = [
            "Verify whether scheduled system maintenance or administrative updates were in progress.",
            "Inspect the technical event log in Section G below.",
            "Escalate to the system administrator if the change or connection was unplanned."
        ]
        category = ", ".join(groups[:3]) if groups else "Security & Network Monitoring"
        condition = f"Triggered Wazuh Security Rule {rule_id_str}"

    return category, condition, what_happened, actions


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

    rule_id = rule.get("id", "N/A")
    rule_level = int(rule.get("level", 0))
    rule_desc = rule.get("description", "Security Alert")
    groups = rule.get("groups", [])
    firedtimes = rule.get("firedtimes", 1)

    agent_name = agent.get("name", "unknown-host")
    agent_id = agent.get("id", "000")
    agent_ip = agent.get("ip", "127.0.0.1 (Local Server)")

    timestamp_raw = alert.get("timestamp", datetime.utcnow().isoformat())
    full_log = alert.get("full_log", "No raw log entry available.")
    location = alert.get("location", "N/A")

    srcip = data.get("srcip") or data.get("audit", {}).get("srcip") or "N/A"
    srcport = data.get("srcport") or "22"
    dstuser = (
        data.get("dstuser")
        or data.get("srcuser")
        or data.get("audit", {}).get("auid")
        or syscheck.get("audit", {}).get("user", {}).get("name")
        or "N/A"
    )
    file_path = data.get("file") or syscheck.get("path") or "N/A"
    protocol = data.get("protocol") or "TCP"

    if "authentication_failed" in groups or "authentication_failures" in groups or "ssh_brute_force" in groups:
        auth_status = "FAILED (Authentication Rejected)"
    elif "authentication_success" in groups:
        auth_status = "SUCCESS (Authenticated)"
    else:
        auth_status = "N/A (System / Network / File Event)"

    severity_label, priority_tag, badge_color, bg_tint = get_severity_info(rule_level)
    category, condition, what_happened, actions = build_guidance(rule_id, groups, srcip, dstuser, file_path)

    subject = f"[{priority_tag}] {rule_desc} | Server: {agent_name}"

    actions_html = "".join(f"<li style='margin-bottom:6px;'>{html.escape(a)}</li>" for a in actions)
    actions_text = "\n".join(f"  {idx+1}. {a}" for idx, a in enumerate(actions))

    plain_text_body = f"""========================================================================
[{priority_tag}] SECURITY INCIDENT NOTIFICATION
========================================================================

A. SECURITY ALERT SUMMARY
- Alert Title:         {rule_desc}
- Severity:            {severity_label} (Level {rule_level})
- Alert Category:      {category}
- Detection Timestamp: {timestamp_raw}
- Summary:             {what_happened}

B. AFFECTED SERVER
- Server Hostname:     {agent_name}
- Server IP Address:   {agent_ip}
- Agent Name / ID:     {agent_name} (ID: {agent_id})
- Operating System:    Red Hat Enterprise Linux 9.8 ({location})

C. ATTACK INFORMATION
- Source IP Address:   {srcip}
- Target Username:     {dstuser}
- Destination Port:    {srcport}
- Protocol:            {protocol}
- Attempt Count:       {firedtimes}
- Auth Status:         {auth_status}
- Target File Path:    {file_path}

D. SECURITY RULE INFORMATION
- Rule ID:             {rule_id}
- Rule Name / Desc:    {rule_desc}
- Alert Level:         {rule_level}
- Detection Condition: {condition}

E. WHAT HAPPENED?
{what_happened}

F. RECOMMENDED ACTIONS
{actions_text}

G. TECHNICAL EVENT DETAILS
{full_log}
========================================================================
"""

    html_body = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
</head>
<body style="margin:0;padding:20px;background-color:#f3f4f6;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#1f2937;">
  <table width="100%" cellpadding="0" cellspacing="0" style="max-width:720px;margin:0 auto;background-color:#ffffff;border:1px solid #d1d5db;border-radius:8px;overflow:hidden;">
    <tr>
      <td style="background-color:{badge_color};color:#ffffff;padding:18px 24px;">
        <div style="font-size:12px;font-weight:700;letter-spacing:1px;text-transform:uppercase;opacity:0.9;">
          Security Incident Notification &bull; {html.escape(severity_label)} Severity
        </div>
        <div style="font-size:20px;font-weight:700;margin-top:4px;">
          {html.escape(rule_desc)}
        </div>
      </td>
    </tr>

    <tr>
      <td style="padding:24px;">
        <h3 style="margin:0 0 12px 0;font-size:15px;color:#111827;border-bottom:2px solid #e5e7eb;padding-bottom:6px;">
          A. Security Alert Summary
        </h3>
        <table width="100%" cellpadding="6" cellspacing="0" style="font-size:14px;margin-bottom:20px;">
          <tr>
            <td width="34%" style="font-weight:600;color:#4b5563;">Alert Title:</td>
            <td><strong>{html.escape(rule_desc)}</strong></td>
          </tr>
          <tr>
            <td style="font-weight:600;color:#4b5563;">Severity:</td>
            <td>
              <span style="background-color:{bg_tint};color:{badge_color};border:1px solid {badge_color};padding:2px 8px;border-radius:4px;font-weight:700;font-size:12px;">
                {html.escape(severity_label)} (Level {rule_level})
              </span>
            </td>
          </tr>
          <tr>
            <td style="font-weight:600;color:#4b5563;">Alert Category:</td>
            <td>{html.escape(category)}</td>
          </tr>
          <tr>
            <td style="font-weight:600;color:#4b5563;">Detection Timestamp:</td>
            <td>{html.escape(str(timestamp_raw))}</td>
          </tr>
        </table>

        <h3 style="margin:0 0 12px 0;font-size:15px;color:#111827;border-bottom:2px solid #e5e7eb;padding-bottom:6px;">
          B. Affected Server
        </h3>
        <table width="100%" cellpadding="6" cellspacing="0" style="font-size:14px;margin-bottom:20px;">
          <tr>
            <td width="34%" style="font-weight:600;color:#4b5563;">Server Hostname / Agent:</td>
            <td><strong>{html.escape(str(agent_name))}</strong> (Agent ID: {html.escape(str(agent_id))})</td>
          </tr>
          <tr>
            <td style="font-weight:600;color:#4b5563;">Server IP Address:</td>
            <td>{html.escape(str(agent_ip))}</td>
          </tr>
          <tr>
            <td style="font-weight:600;color:#4b5563;">Operating System / Log:</td>
            <td>Red Hat Enterprise Linux 9.8 &bull; <code>{html.escape(str(location))}</code></td>
          </tr>
        </table>

        <h3 style="margin:0 0 12px 0;font-size:15px;color:#111827;border-bottom:2px solid #e5e7eb;padding-bottom:6px;">
          C. Attack Information
        </h3>
        <table width="100%" cellpadding="6" cellspacing="0" style="font-size:14px;margin-bottom:20px;background-color:#f9fafb;border:1px solid #e5e7eb;border-radius:6px;">
          <tr>
            <td width="34%" style="font-weight:600;color:#4b5563;">Source IP Address:</td>
            <td><strong style="color:#b91c1c;">{html.escape(str(srcip))}</strong></td>
          </tr>
          <tr>
            <td style="font-weight:600;color:#4b5563;">Target Username:</td>
            <td><strong>{html.escape(str(dstuser))}</strong></td>
          </tr>
          <tr>
            <td style="font-weight:600;color:#4b5563;">Destination Port / Proto:</td>
            <td>{html.escape(str(srcport))} / {html.escape(str(protocol))}</td>
          </tr>
          <tr>
            <td style="font-weight:600;color:#4b5563;">Attempt Count:</td>
            <td>{html.escape(str(firedtimes))}</td>
          </tr>
          <tr>
            <td style="font-weight:600;color:#4b5563;">Authentication Status:</td>
            <td>{html.escape(str(auth_status))}</td>
          </tr>
          <tr>
            <td style="font-weight:600;color:#4b5563;">Target File Path:</td>
            <td><code>{html.escape(str(file_path))}</code></td>
          </tr>
        </table>

        <h3 style="margin:0 0 12px 0;font-size:15px;color:#111827;border-bottom:2px solid #e5e7eb;padding-bottom:6px;">
          D. Security Rule Information
        </h3>
        <table width="100%" cellpadding="6" cellspacing="0" style="font-size:14px;margin-bottom:20px;">
          <tr>
            <td width="34%" style="font-weight:600;color:#4b5563;">Rule ID &amp; Level:</td>
            <td>Rule <strong>{html.escape(str(rule_id))}</strong> (Level {rule_level})</td>
          </tr>
          <tr>
            <td style="font-weight:600;color:#4b5563;">Rule Description:</td>
            <td>{html.escape(rule_desc)}</td>
          </tr>
          <tr>
            <td style="font-weight:600;color:#4b5563;">Detection Condition:</td>
            <td>{html.escape(condition)}</td>
          </tr>
        </table>

        <h3 style="margin:0 0 10px 0;font-size:15px;color:#111827;border-bottom:2px solid #e5e7eb;padding-bottom:6px;">
          E. What Happened?
        </h3>
        <div style="background-color:{bg_tint};border-left:4px solid {badge_color};padding:12px 16px;font-size:14px;line-height:1.5;margin-bottom:20px;">
          {html.escape(what_happened)}
        </div>

        <h3 style="margin:0 0 10px 0;font-size:15px;color:#111827;border-bottom:2px solid #e5e7eb;padding-bottom:6px;">
          F. Recommended Actions
        </h3>
        <ol style="margin:0 0 20px 0;padding-left:20px;font-size:14px;line-height:1.5;">
          {actions_html}
        </ol>

        <h3 style="margin:0 0 10px 0;font-size:15px;color:#111827;border-bottom:2px solid #e5e7eb;padding-bottom:6px;">
          G. Technical Event Details
        </h3>
        <pre style="background-color:#111827;color:#f9fafb;padding:12px;border-radius:6px;font-size:12px;overflow-x:auto;white-space:pre-wrap;word-break:break-all;margin:0;">{html.escape(str(full_log))}</pre>
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
```

#### Commands:
```bash
sudo tee /var/ossec/integrations/custom-html-email.py << 'EOF'
#!/var/ossec/framework/python/bin/python3
# -*- coding: utf-8 -*-
import sys
import json
import smtplib
import html
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

SMTP_SERVER = "127.0.0.1"
SMTP_PORT = 25
SENDER_EMAIL = "devops.jakir@gmail.com"
RECIPIENT_EMAILS = ["hiddenclue0@gmail.com"]


def get_severity_info(level):
    if level >= 13:
        return "CRITICAL", "CRITICAL PRIORITY", "#b91c1c", "#fef2f2"
    elif level >= 11:
        return "HIGH", "HIGH PRIORITY", "#c2410c", "#fff7ed"
    elif level >= 7:
        return "MEDIUM", "MEDIUM PRIORITY", "#b45309", "#fffbeb"
    else:
        return "LOW", "LOW PRIORITY", "#1d4ed8", "#eff6ff"


def build_guidance(rule_id, groups, srcip, dstuser, file_path):
    rule_id_str = str(rule_id)

    if rule_id_str in ("100601", "100602"):
        what_happened = (
            f"An external or internal host ({srcip}) attempted to access the SSH service on this server "
            f"targeting user '{dstuser}' using repeated incorrect passwords. Five failed authentication "
            f"attempts were detected within five minutes. This activity may indicate an SSH brute-force attack."
        )
        actions = [
            f"Verify whether the source IP address ({srcip}) is authorized.",
            f"Check whether the targeted username ('{dstuser}') belongs to an active employee.",
            "Review recent successful login events to confirm no unauthorized access occurred.",
            "Contact the system administrator if the activity is unexpected.",
            f"Consider blocking the source IP ({srcip}) after investigation."
        ]
        category = "SSH Brute-Force Attack"
        condition = "5 failed SSH authentication attempts within 5 minutes (300 seconds)"

    elif rule_id_str == "100603":
        what_happened = (
            f"User account '{dstuser}' received successful SSH login events from two different source IP "
            f"addresses (most recently {srcip}) within five minutes. While this can occur when an engineer "
            f"switches networks or VPNs, it requires investigation for credential sharing or unauthorized access."
        )
        actions = [
            f"Confirm with employee '{dstuser}' whether they connected from two different workstations or networks.",
            "Verify whether both source IP addresses belong to known corporate subnets.",
            f"Ensure engineers are not sharing the '{dstuser}' account credentials.",
            f"If the login from {srcip} is unauthorized, terminate active sessions and rotate the account password."
        ]
        category = "Suspicious Multi-IP SSH Access"
        condition = "Same username authenticated from 2 different source IPs within 5 minutes"

    elif rule_id_str == "100604":
        what_happened = (
            f"A single source IP address ({srcip}) attempted SSH authentication against multiple distinct "
            f"usernames (most recently '{dstuser}') within five minutes. This behavior indicates potential "
            f"username enumeration or password spraying."
        )
        actions = [
            f"Verify whether source IP {srcip} is an authorized scanner or administrator host.",
            "Check if any targeted usernames are default or inactive accounts.",
            f"Block {srcip} at the firewall or AWS Security Group if unauthorized."
        ]
        category = "SSH Username Enumeration"
        condition = "4 failed SSH authentication attempts against distinct usernames from 1 IP within 5 minutes"

    elif rule_id_str == "100605":
        what_happened = (
            f"CRITICAL ALERT: Source IP {srcip} achieved a successful SSH login into user '{dstuser}' "
            f"immediately following repeated failed authentication attempts. The account may be compromised."
        )
        actions = [
            f"Contact '{dstuser}' immediately to verify if they just logged in from {srcip}.",
            f"If unexpected, lock the user account ('sudo usermod -L {dstuser}') and terminate their SSH session.",
            "Review all executed commands in the Wazuh Dashboard (Rule 80792).",
            "Reset the user's password and SSH authorized_keys immediately."
        ]
        category = "Successful Login After Brute-Force"
        condition = "Successful SSH login (Rule 5715) within 5 minutes of brute-force alert (Rule 100601)"

    elif rule_id_str in ("100606", "100607"):
        what_happened = (
            f"A direct SSH login attempt using the privileged 'root' account was detected from IP {srcip}. "
            f"Direct root logins obscure individual administrator accountability."
        )
        actions = [
            f"Verify which administrator initiated the root SSH session from {srcip}.",
            "Instruct administrators to log in with personal accounts and use sudo.",
            "Set 'PermitRootLogin no' in /etc/ssh/sshd_config if direct root SSH is not required."
        ]
        category = "Root SSH Login Activity"
        condition = "Direct SSH login event targeting user 'root'"

    elif rule_id_str in ("100501", "100502", "100503", "100504", "100505"):
        what_happened = (
            f"An SFTP file transfer or restricted SFTP access attempt occurred involving user '{dstuser}' "
            f"(Target file: {file_path}). All SFTP file uploads, downloads, deletions, and blocked attempts "
            f"are tracked for intellectual property protection."
        )
        actions = [
            f"Verify whether user '{dstuser}' is authorized to transfer or modify '{file_path}'.",
            "If Rule 100505 triggered, an SFTP-restricted VNC user attempted to use SFTP and was blocked.",
            "Contact the engineering security team if unauthorized design files were transferred."
        ]
        category = "SFTP File Transfer & Access Control"
        condition = "SFTP session, file read/write/delete, or blocked group access attempt"

    else:
        what_happened = (
            "Wazuh detected a suspicious SSH, network port, or configuration change event on the monitored "
            "server. Please review the affected server and technical details below."
        )
        actions = [
            "Verify whether scheduled system maintenance or administrative updates were in progress.",
            "Inspect the technical event log in Section G below.",
            "Escalate to the system administrator if the change or connection was unplanned."
        ]
        category = ", ".join(groups[:3]) if groups else "Security & Network Monitoring"
        condition = f"Triggered Wazuh Security Rule {rule_id_str}"

    return category, condition, what_happened, actions


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

    rule_id = rule.get("id", "N/A")
    rule_level = int(rule.get("level", 0))
    rule_desc = rule.get("description", "Security Alert")
    groups = rule.get("groups", [])
    firedtimes = rule.get("firedtimes", 1)

    agent_name = agent.get("name", "unknown-host")
    agent_id = agent.get("id", "000")
    agent_ip = agent.get("ip", "127.0.0.1 (Local Server)")

    timestamp_raw = alert.get("timestamp", datetime.utcnow().isoformat())
    full_log = alert.get("full_log", "No raw log entry available.")
    location = alert.get("location", "N/A")

    srcip = data.get("srcip") or data.get("audit", {}).get("srcip") or "N/A"
    srcport = data.get("srcport") or "22"
    dstuser = (
        data.get("dstuser")
        or data.get("srcuser")
        or data.get("audit", {}).get("auid")
        or syscheck.get("audit", {}).get("user", {}).get("name")
        or "N/A"
    )
    file_path = data.get("file") or syscheck.get("path") or "N/A"
    protocol = data.get("protocol") or "TCP"

    if "authentication_failed" in groups or "authentication_failures" in groups or "ssh_brute_force" in groups:
        auth_status = "FAILED (Authentication Rejected)"
    elif "authentication_success" in groups:
        auth_status = "SUCCESS (Authenticated)"
    else:
        auth_status = "N/A (System / Network / File Event)"

    severity_label, priority_tag, badge_color, bg_tint = get_severity_info(rule_level)
    category, condition, what_happened, actions = build_guidance(rule_id, groups, srcip, dstuser, file_path)

    subject = f"[{priority_tag}] {rule_desc} | Server: {agent_name}"

    actions_html = "".join(f"<li style='margin-bottom:6px;'>{html.escape(a)}</li>" for a in actions)
    actions_text = "\n".join(f"  {idx+1}. {a}" for idx, a in enumerate(actions))

    plain_text_body = f"""========================================================================
[{priority_tag}] SECURITY INCIDENT NOTIFICATION
========================================================================

A. SECURITY ALERT SUMMARY
- Alert Title:         {rule_desc}
- Severity:            {severity_label} (Level {rule_level})
- Alert Category:      {category}
- Detection Timestamp: {timestamp_raw}
- Summary:             {what_happened}

B. AFFECTED SERVER
- Server Hostname:     {agent_name}
- Server IP Address:   {agent_ip}
- Agent Name / ID:     {agent_name} (ID: {agent_id})
- Operating System:    Red Hat Enterprise Linux 9.8 ({location})

C. ATTACK INFORMATION
- Source IP Address:   {srcip}
- Target Username:     {dstuser}
- Destination Port:    {srcport}
- Protocol:            {protocol}
- Attempt Count:       {firedtimes}
- Auth Status:         {auth_status}
- Target File Path:    {file_path}

D. SECURITY RULE INFORMATION
- Rule ID:             {rule_id}
- Rule Name / Desc:    {rule_desc}
- Alert Level:         {rule_level}
- Detection Condition: {condition}

E. WHAT HAPPENED?
{what_happened}

F. RECOMMENDED ACTIONS
{actions_text}

G. TECHNICAL EVENT DETAILS
{full_log}
========================================================================
"""

    html_body = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
</head>
<body style="margin:0;padding:20px;background-color:#f3f4f6;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#1f2937;">
  <table width="100%" cellpadding="0" cellspacing="0" style="max-width:720px;margin:0 auto;background-color:#ffffff;border:1px solid #d1d5db;border-radius:8px;overflow:hidden;">
    <tr>
      <td style="background-color:{badge_color};color:#ffffff;padding:18px 24px;">
        <div style="font-size:12px;font-weight:700;letter-spacing:1px;text-transform:uppercase;opacity:0.9;">
          Security Incident Notification &bull; {html.escape(severity_label)} Severity
        </div>
        <div style="font-size:20px;font-weight:700;margin-top:4px;">
          {html.escape(rule_desc)}
        </div>
      </td>
    </tr>

    <tr>
      <td style="padding:24px;">
        <h3 style="margin:0 0 12px 0;font-size:15px;color:#111827;border-bottom:2px solid #e5e7eb;padding-bottom:6px;">
          A. Security Alert Summary
        </h3>
        <table width="100%" cellpadding="6" cellspacing="0" style="font-size:14px;margin-bottom:20px;">
          <tr>
            <td width="34%" style="font-weight:600;color:#4b5563;">Alert Title:</td>
            <td><strong>{html.escape(rule_desc)}</strong></td>
          </tr>
          <tr>
            <td style="font-weight:600;color:#4b5563;">Severity:</td>
            <td>
              <span style="background-color:{bg_tint};color:{badge_color};border:1px solid {badge_color};padding:2px 8px;border-radius:4px;font-weight:700;font-size:12px;">
                {html.escape(severity_label)} (Level {rule_level})
              </span>
            </td>
          </tr>
          <tr>
            <td style="font-weight:600;color:#4b5563;">Alert Category:</td>
            <td>{html.escape(category)}</td>
          </tr>
          <tr>
            <td style="font-weight:600;color:#4b5563;">Detection Timestamp:</td>
            <td>{html.escape(str(timestamp_raw))}</td>
          </tr>
        </table>

        <h3 style="margin:0 0 12px 0;font-size:15px;color:#111827;border-bottom:2px solid #e5e7eb;padding-bottom:6px;">
          B. Affected Server
        </h3>
        <table width="100%" cellpadding="6" cellspacing="0" style="font-size:14px;margin-bottom:20px;">
          <tr>
            <td width="34%" style="font-weight:600;color:#4b5563;">Server Hostname / Agent:</td>
            <td><strong>{html.escape(str(agent_name))}</strong> (Agent ID: {html.escape(str(agent_id))})</td>
          </tr>
          <tr>
            <td style="font-weight:600;color:#4b5563;">Server IP Address:</td>
            <td>{html.escape(str(agent_ip))}</td>
          </tr>
          <tr>
            <td style="font-weight:600;color:#4b5563;">Operating System / Log:</td>
            <td>Red Hat Enterprise Linux 9.8 &bull; <code>{html.escape(str(location))}</code></td>
          </tr>
        </table>

        <h3 style="margin:0 0 12px 0;font-size:15px;color:#111827;border-bottom:2px solid #e5e7eb;padding-bottom:6px;">
          C. Attack Information
        </h3>
        <table width="100%" cellpadding="6" cellspacing="0" style="font-size:14px;margin-bottom:20px;background-color:#f9fafb;border:1px solid #e5e7eb;border-radius:6px;">
          <tr>
            <td width="34%" style="font-weight:600;color:#4b5563;">Source IP Address:</td>
            <td><strong style="color:#b91c1c;">{html.escape(str(srcip))}</strong></td>
          </tr>
          <tr>
            <td style="font-weight:600;color:#4b5563;">Target Username:</td>
            <td><strong>{html.escape(str(dstuser))}</strong></td>
          </tr>
          <tr>
            <td style="font-weight:600;color:#4b5563;">Destination Port / Proto:</td>
            <td>{html.escape(str(srcport))} / {html.escape(str(protocol))}</td>
          </tr>
          <tr>
            <td style="font-weight:600;color:#4b5563;">Attempt Count:</td>
            <td>{html.escape(str(firedtimes))}</td>
          </tr>
          <tr>
            <td style="font-weight:600;color:#4b5563;">Authentication Status:</td>
            <td>{html.escape(str(auth_status))}</td>
          </tr>
          <tr>
            <td style="font-weight:600;color:#4b5563;">Target File Path:</td>
            <td><code>{html.escape(str(file_path))}</code></td>
          </tr>
        </table>

        <h3 style="margin:0 0 12px 0;font-size:15px;color:#111827;border-bottom:2px solid #e5e7eb;padding-bottom:6px;">
          D. Security Rule Information
        </h3>
        <table width="100%" cellpadding="6" cellspacing="0" style="font-size:14px;margin-bottom:20px;">
          <tr>
            <td width="34%" style="font-weight:600;color:#4b5563;">Rule ID &amp; Level:</td>
            <td>Rule <strong>{html.escape(str(rule_id))}</strong> (Level {rule_level})</td>
          </tr>
          <tr>
            <td style="font-weight:600;color:#4b5563;">Rule Description:</td>
            <td>{html.escape(rule_desc)}</td>
          </tr>
          <tr>
            <td style="font-weight:600;color:#4b5563;">Detection Condition:</td>
            <td>{html.escape(condition)}</td>
          </tr>
        </table>

        <h3 style="margin:0 0 10px 0;font-size:15px;color:#111827;border-bottom:2px solid #e5e7eb;padding-bottom:6px;">
          E. What Happened?
        </h3>
        <div style="background-color:{bg_tint};border-left:4px solid {badge_color};padding:12px 16px;font-size:14px;line-height:1.5;margin-bottom:20px;">
          {html.escape(what_happened)}
        </div>

        <h3 style="margin:0 0 10px 0;font-size:15px;color:#111827;border-bottom:2px solid #e5e7eb;padding-bottom:6px;">
          F. Recommended Actions
        </h3>
        <ol style="margin:0 0 20px 0;padding-left:20px;font-size:14px;line-height:1.5;">
          {actions_html}
        </ol>

        <h3 style="margin:0 0 10px 0;font-size:15px;color:#111827;border-bottom:2px solid #e5e7eb;padding-bottom:6px;">
          G. Technical Event Details
        </h3>
        <pre style="background-color:#111827;color:#f9fafb;padding:12px;border-radius:6px;font-size:12px;overflow-x:auto;white-space:pre-wrap;word-break:break-all;margin:0;">{html.escape(str(full_log))}</pre>
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

sudo chown root:wazuh /var/ossec/integrations/custom-html-email.py
sudo chmod 750 /var/ossec/integrations/custom-html-email.py
```

---

### Step 18: Validate and Restart `wazuh-manager` to Activate All Rules & HTML Email Integration
* **Server:** Wazuh Manager (`wazuh-server` — `11.11.2.165`, RHEL 9.8)

#### Commands:
```bash
sudo /var/ossec/framework/python/bin/python3 -m py_compile /var/ossec/integrations/custom-html-email.py
sudo /var/ossec/bin/wazuh-analysisd -t && sudo systemctl restart wazuh-manager
```

#### Validation:
```bash
sudo systemctl status wazuh-manager --no-pager
ps aux | grep wazuh-integratord
```

#### Expected Result:
`wazuh-manager` is `active (running)` and `wazuh-integratord` is running in the process list.

---

## Section 8: Phase 7 – End-to-End Testing and Validation

This phase validates the Wazuh deployment using realistic manual testing. Rather than injecting artificial log messages, these tests use real network connections from separate Linux testing machines to confirm that the Wazuh Agent successfully captures raw OS events, the Manager correctly decodes and correlates them, and the Custom HTML Email integration reliably delivers alerts.

### Pre-Test Safety and Environment Setup

**Important:** Do not perform brute-force testing against production accounts to avoid accidental PAM lockouts. Create a dedicated test account on the monitored Wazuh Agent.

**On the Monitored Agent (`vnc-server`):**

```bash
# Create a dedicated testing account
sudo useradd wazuh-tester
sudo passwd wazuh-tester  # Set a known, temporary password

# Ensure SFTP testing is permitted for this user (if using the groups from earlier phases)
sudo usermod -aG sftp-allowed wazuh-tester

```

---

### Test 1: SSH Brute-Force Detection (5 Failed Attempts)

**A. Test Objective**
Validate that 5 failed SSH authentication attempts from a single IP within 5 minutes trigger a brute-force alert.

**B. Test Environment**

* **Testing Machine:** A separate Linux workstation/server (e.g., IP: `192.168.1.100`).
* **Target Agent:** `vnc-server` (`11.11.2.213`).
* **Test Username:** `wazuh-tester`.

**C. Manual Testing Instructions**
From your testing machine, execute the SSH command 5 times rapidly. Each time you are prompted for a password, enter an intentionally *incorrect* password.

```bash
ssh wazuh-tester@11.11.2.213
# Type a fake password, press Enter. Wait for "Permission denied". Repeat 4 more times.

```

**D. Expected Result**

* **Triggered Rule:** `100601` (Level 12).
* **Alert Information:** "SSH Brute-Force Attack Detected: 5 failed login attempts within 5 minutes..."
* **Email Action:** A high-priority HTML email is generated and sent to the configured recipient containing the attacker's IP and targeted user.

**E. Verification on Wazuh Manager**
Log into the Wazuh Manager and verify the alert and email dispatch:

```bash
sudo grep "100601" /var/ossec/logs/alerts/alerts.log
sudo grep "wazuh-tester" /var/log/maillog

```

---

### Test 2: Successful SSH Login

**A. Test Objective**
Validate that a standard successful SSH authentication is logged accurately without triggering a brute-force or high-severity alert.

**B. Test Environment**

* **Testing Machine:** A single authorized Linux workstation.
* **Target Agent:** `vnc-server` (`11.11.2.213`).
* **Test Username:** `wazuh-tester`.

**C. Manual Testing Instructions**
From your testing machine, authenticate successfully:

```bash
ssh wazuh-tester@11.11.2.213
# Enter the correct password to access the shell.
# Type 'exit' to close the session.

```

**D. Expected Result**

* **Triggered Rule:** Built-in Rule `5715` (Level 3).
* **Alert Information:** "sshd: authentication success."
* **Email Action:** No email should be sent (level is below the default email threshold and no explicit email option is attached).

**E. Verification on Wazuh Manager**

```bash
sudo grep "5715" /var/ossec/logs/alerts/alerts.log | grep "wazuh-tester"

```

---

### Test 3: Same Username Accessed from Multiple IP Addresses

**A. Test Objective**
Verify detection of a suspicious scenario where the same user account successfully authenticates from two genuinely distinct network locations within 5 minutes.

**B. Test Environment**

* **Testing Machines:** *Machine A* (e.g., `192.168.1.100`) and *Machine B* (e.g., `10.0.5.50`). You must use two distinct network interfaces or servers.
* **Target Agent:** `vnc-server` (`11.11.2.213`).
* **Test Username:** `wazuh-tester`.

**C. Manual Testing Instructions**

1. From **Machine A**, log in successfully:
```bash
ssh wazuh-tester@11.11.2.213

```


2. Within 5 minutes, from **Machine B**, log in successfully:
```bash
ssh wazuh-tester@11.11.2.213

```



**D. Expected Result**

* **Triggered Rule:** `100603` (Level 11).
* **Alert Information:** "Suspicious Concurrent SSH Access: User wazuh-tester logged in from multiple different IP addresses..."
* **Email Action:** An HTML email notification is sent outlining both the target user and the latest source IP.

**E. Verification on Wazuh Manager**

```bash
sudo grep "100603" /var/ossec/logs/alerts/alerts.log

```

---

### Test 4: Username Enumeration / Spraying

**A. Test Objective**
Detect a single source IP attempting to log in across multiple non-existent or varying usernames (spraying) within 5 minutes.

**B. Test Environment**

* **Testing Machine:** A single Linux workstation.
* **Target Agent:** `vnc-server` (`11.11.2.213`).
* **Test Usernames:** `fakeuser1`, `fakeuser2`, `fakeuser3`, `fakeuser4`.

**C. Manual Testing Instructions**
From the testing machine, attempt SSH access sequentially using different invalid usernames. Provide a fake password for each.

```bash
ssh fakeuser1@11.11.2.213
ssh fakeuser2@11.11.2.213
ssh fakeuser3@11.11.2.213
ssh fakeuser4@11.11.2.213

```

**D. Expected Result**

* **Triggered Rule:** `100604` (Level 12).
* **Alert Information:** "SSH Username Enumeration / Spraying Detected: Source IP failed authentication against multiple distinct usernames..."
* **Email Action:** An HTML email is dispatched highlighting the attacking IP.

**E. Verification on Wazuh Manager**

```bash
sudo grep "100604" /var/ossec/logs/alerts/alerts.log

```

---

### Test 5: Direct Root SSH Login

**A. Test Objective**
Validate that any successful direct authentication as the `root` user is flagged immediately.

**B. Test Environment**

* **Testing Machine:** A single Linux workstation.
* **Target Agent:** `vnc-server` (`11.11.2.213`).
* **Prerequisite:** Temporarily set `PermitRootLogin yes` in `/etc/ssh/sshd_config` on the Agent and reload `sshd` to allow the test to succeed.

**C. Manual Testing Instructions**
From the testing machine, authenticate as `root`:

```bash
ssh root@11.11.2.213
# Enter the root password.
# Immediately log out and revert PermitRootLogin if prohibited by policy.

```

**D. Expected Result**

* **Triggered Rule:** `100606` (Level 12).
* **Alert Information:** "Direct Root SSH Login Succeeded from IP..."
* **Email Action:** A critical HTML email notification is generated.

**E. Verification on Wazuh Manager**

```bash
sudo grep "100606" /var/ossec/logs/alerts/alerts.log

```

---

### Test 6: Successful Login Following Repeated Failures

**A. Test Objective**
Detect a high-risk compromise indicator: an attacker successfully guessing a password immediately after a brute-force attack.

**B. Test Environment**

* **Testing Machine:** A single Linux workstation.
* **Target Agent:** `vnc-server` (`11.11.2.213`).
* **Test Username:** `wazuh-tester`.

**C. Manual Testing Instructions**

1. From the testing machine, trigger the brute-force rule by attempting 5 SSH connections with an incorrect password.
2. On the 6th attempt (within the same 5-minute window), authenticate using the *correct* password.

```bash
# 5 times with bad password:
ssh wazuh-tester@11.11.2.213
# 1 time with good password:
ssh wazuh-tester@11.11.2.213

```

**D. Expected Result**

* **Triggered Rule:** `100605` (Level 14).
* **Alert Information:** "CRITICAL: Successful SSH login... immediately following an SSH brute-force attack."
* **Email Action:** A critical severity HTML email is dispatched immediately.

**E. Verification on Wazuh Manager**

```bash
sudo grep "100605" /var/ossec/logs/alerts/alerts.log

```

---

### Test 7: SFTP File Upload Alert

**A. Test Objective**
Ensure `internal-sftp` subsystem logging correctly decodes and triggers alerts for file uploads.

**B. Test Environment**

* **Testing Machine:** A single Linux workstation.
* **Target Agent:** `vnc-server` (`11.11.2.213`).
* **Test Username:** `wazuh-tester`.

**C. Manual Testing Instructions**
Create a dummy file on your testing machine and upload it via SFTP:

```bash
echo "Malicious payload test" > sftp-test.txt
sftp wazuh-tester@11.11.2.213
# At the sftp> prompt:
sftp> put sftp-test.txt
sftp> exit

```

**D. Expected Result**

* **Triggered Rule:** `100502` (Level 12).
* **Alert Information:** "SFTP File Upload/Write Detected: File 'sftp-test.txt' opened..."
* **Email Action:** An HTML email is dispatched identifying the uploaded file and user.

**E. Verification on Wazuh Manager**

```bash
sudo grep "100502" /var/ossec/logs/alerts/alerts.log

```

---

### Test 8: Suspicious New Listening Port Detection

**A. Test Objective**
Validate that Wazuh detects rogue services opening new TCP/UDP listening ports on the monitored agent.

**B. Test Environment**

* **Testing Machine:** The Wazuh Agent itself (`vnc-server`).
* **Prerequisite:** `nc` (netcat) or `python3` installed.

**C. Manual Testing Instructions**
Log into the Agent locally or via SSH and open a temporary, unauthorized listening port (e.g., 9999).

```bash
# Option A: using netcat
nc -l -p 9999

# Option B: using python3
python3 -m http.server 9999

```

Leave the terminal open and running. Wazuh polls the `netstat` / `ss` output command every 60 seconds (per `localfile` configuration). Wait up to 2 minutes.

**D. Expected Result**

* **Triggered Rule:** `100620` (Level 10).
* **Alert Information:** "Network Port Change Detected: Active TCP/UDP listening sockets changed on server."
* **Email Action:** An HTML email is dispatched showing the output differential (the new port 9999).

**E. Verification on Wazuh Manager**

```bash
sudo grep "100620" /var/ossec/logs/alerts/alerts.log

```

### Post-Test Cleanup

Once validation is complete, securely remove the test account from the Agent server to prevent unauthorized access.
**On the Monitored Agent (`vnc-server`):**

```bash
# Kill the listening port process (Ctrl+C in the terminal or kill by PID)
sudo userdel -r wazuh-tester

```

---

## 9. Troubleshooting Reference

| Issue / Error | Diagnostic Command | Root Cause & Fix |
| :--- | :--- | :--- |
| **1. `wazuh-dashboard` fails during install & rolls back** | `sudo tail -n 50 /var/log/wazuh-install.log` | Caused by `<50 GB` disk, `0` swap, or missing `fontconfig`/`lsof`/`libcap`. Follow Steps 2–4 before running `wazuh-install.sh`. |
| **2. `Failed to restart auditd.service: Operation refused`** | `sudo augenrules --load` | RHEL 9 locks `auditd` against `systemctl stop/restart`. Always use `sudo augenrules --load` or `sudo service auditd restart`. |
| **3. `Error sending add rule data request (Rule exists)`** | `ls -la /etc/audit/rules.d/` | Duplicate `.rules` files in `/etc/audit/rules.d/` or missing watched directory (`/etc/tigervnc`). Remove duplicate files and `mkdir -p` watched paths (Step 10). |
| **4. `ERROR: (1452): Syntax error on regex` in decoders** | `sudo /var/ossec/bin/wazuh-analysisd -t` | Legacy `OS_Regex` rejects `\[` and `[^"]+`. Always specify `<prematch type="pcre2">` and `<regex type="pcre2">` (Step 13). |
| **5. `XMLERR: Element not closed` in `ossec.conf`** | `sudo /var/ossec/bin/wazuh-analysisd -t` | Malformed XML tag from manual edit. Restore backup or apply clean configuration in Step 12. |
| **6. Multi-IP rule (`100603`) does not fire in `wazuh-logtest`** | Pipe both logs in one `<< 'EOF'` block | `wazuh-logtest` clears correlation memory when exited. Pipe both login events in a single `wazuh-logtest` session and ensure `srcip` differs. |
| **7. Duplicate emails sent for the same alert** | `sudo grep "status=sent" /var/log/maillog` | Caused by having `<email_notification>yes</email_notification>` enabled alongside `custom-html-email.py`. Keep `<email_notification>no</email_notification>` in `<global>`. |
| **8. `custom-html-email.py` does not execute** | `sudo grep "integratord" /var/ossec/logs/ossec.log` | Verify ownership is `root:wazuh`, permissions are `750`, and shebang is `#!/var/ossec/framework/python/bin/python3`. |
| **9. Postfix `Network is unreachable` IPv6 delay** | `sudo postconf inet_protocols` | EC2 instance lacks IPv6 route to `smtp.gmail.com`. Run `sudo postconf -e "inet_protocols = ipv4"` and `sudo systemctl restart postfix`. |

---

## 10. Production Readiness, Hardening & Backup Checklist

### Step 19: Create Automated Configuration Backup Archive
* **Server:** Wazuh Manager (`wazuh-server` — `11.11.2.165`, RHEL 9.8)

#### Commands:
```bash
sudo tar -czvf /root/wazuh-production-config-backup-$(date +%F).tar.gz \
  /root/wazuh-install-files-backup.tar \
  /var/ossec/etc/ossec.conf \
  /var/ossec/etc/client.keys \
  /var/ossec/etc/decoders/sftp_decoders.xml \
  /var/ossec/etc/rules/sftp_and_vnc_rules.xml \
  /var/ossec/etc/rules/ssh_and_network_rules.xml \
  /var/ossec/integrations/custom-html-email.py \
  /etc/postfix/main.cf \
  /etc/postfix/sasl_passwd

sudo chmod 600 /root/wazuh-production-config-backup-*.tar.gz
```

#### Validation:
```bash
sudo ls -lh /root/wazuh-production-config-backup-*.tar.gz
```

#### Expected Result:
Encrypted/root-only backup archive (`-rw------- 1 root root`) is created in `/root/`.

### Final Verification Matrix

| Step | Component | Target Server | Status |
| :--- | :--- | :--- | :--- |
| **Steps 1–4** | RHEL 9.8 Kernel Upgrade, 4 GB Swap, 100 GB XFS Disk, DNF & Dependencies | `wazuh-server` | **Completed** |
| **Steps 5–6** | Wazuh v4.14.9 All-in-One Installation, Cert Backup, Repo Lock | `wazuh-server` | **Completed** |
| **Steps 7–8** | Wazuh Agent v4.14.9 RPM Installation, Registration & 1s Loop Timeout | `vnc-server` | **Completed** |
| **Step 9** | OpenSSH `LogLevel VERBOSE`, `internal-sftp -l INFO`, `sftp-allowed`/`denied` Groups | `vnc-server` | **Completed** |
| **Step 10** | Kernel `auditd` Rules (`execve`, `user-modify`, `vnc`, `sshd`, `network`) | Both Servers | **Completed (Add SSH/Net watches)** |
| **Steps 11–12** | Complete Agent & Manager `ossec.conf` (`whodata="yes"`, `ss -tulpnH`, `<integration>`) | Both Servers | **Ready to Apply** |
| **Steps 13–14** | Custom PCRE2 SFTP Decoders (`sftp_decoders.xml`) & SFTP/VNC Rules (`100501–100506`) | `wazuh-server` | **Completed** |
| **Step 15** | Custom SSH & Network Rules (`100601–100623` in `ssh_and_network_rules.xml`) | `wazuh-server` | **Ready to Apply** |
| **Steps 16–18** | Postfix IPv4 Tuning & Custom Python HTML Email Integration (`custom-html-email.py`) | `wazuh-server` | **Ready to Apply** |
| **Step 19** | Production Configuration & Certificate Backup Archive | `wazuh-server` | **Ready to Apply** |
