# Wazuh v4.14.9 Complete Installation, RHEL 9.8 TigerVNC/SFTP Integration, and Team Management Guide

## 1. Introduction and Architecture

This guide provides the complete, sequential procedure to install a fresh **Wazuh v4.14.9** central server from scratch on **Red Hat Enterprise Linux (RHEL) 9.8**, install and register the **Wazuh Agent**, integrate an existing **RHEL 9.8 TigerVNC and Chrooted SFTP server** without disrupting active services, and configure deduplicated HTML email alerts via **Postfix and Gmail SMTP**.

### 1.1 Wazuh Core Components and Deployment Placement

| Component | Technical Role | Recommended Placement |
| :--- | :--- | :--- |
| **1. Wazuh Indexer** | OpenSearch-based (v2.19.6) distributed search and analytics engine that stores and indexes alerts in JSON format. | Installed **together** on the dedicated **Wazuh Central Server** (`172.31.7.137`) for single-node deployments (up to 50–100 agents). |
| **2. Wazuh Manager** | Analyzes agent telemetry against decoders and rules (`wazuh-analysisd`), manages agent enrollment (`wazuh-authd`), receives encrypted agent streams (`wazuh-remoted`), and triggers integrations (`wazuh-integratord`). | Installed **together** on the **Wazuh Central Server** (`172.31.7.137`) alongside Filebeat (which ships alerts to the Indexer). |
| **3. Wazuh Dashboard** | Web user interface (port `443/TCP`) for threat hunting, File Integrity Monitoring (FIM), vulnerability review, and Role-Based Access Control (RBAC). | Installed **together** on the **Wazuh Central Server** (`172.31.7.137`). |
| **4. Wazuh Agent** | Lightweight host daemon installed on monitored Linux servers (`wazuh-agentd`, `wazuh-logcollector`, `wazuh-syscheckd`, `wazuh-modulesd`). | Installed **separately** on every monitored endpoint (such as `vnc-server` at `172.31.9.50`). Never install the Agent on the Wazuh Manager host. |
| **5. Integrations & Notification Engine** | `wazuh-integratord` + `/var/ossec/integrations/custom-html-email.py` + local **Postfix** STARTTLS relay (`smtp.gmail.com:587`). | Installed on the **Wazuh Central Server** (`172.31.7.137`). |

### 1.2 End-to-End Architecture Diagram

```text
+---------------------------------------------------------------------------------------+
| MONITORED ENDPOINT: vnc-server (172.31.9.50) - RHEL 9.8 (Existing TigerVNC/SFTP Host) |
|                                                                                       |
|  +-------------------------+  +-------------------------+  +-----------------------+  |
|  | /var/log/secure         |  | /srv/sftp/<user>/dev/log|  | /home/*/.local/share/ |  |
|  | (SSHD, PAM, SFTP Auth)  |  | (Bind-mounted journald  |  | tigervnc/*.log        |  |
|  | LogLevel VERBOSE        |  |  socket for Chroot SFTP)|  | (Xvnc Display :1..:N) |  |
|  +------------+------------+  +------------+------------+  +-----------+-----------+  |
|               |                            |                           |              |
|               +----------------------------+---------------------------+              |
|                                            |                                          |
|  +-------------------------+               v                                          |
|  | /var/log/audit/audit.log| ---> wazuh-logcollector & wazuh-syscheckd (Whodata FIM)  |
|  | (execve, passwd, group) |               |                                          |
|  +-------------------------+               v                                          |
|                                      wazuh-agentd                                     |
+--------------------------------------------|------------------------------------------+
                                             |
                        1514/TCP (TLS Events) & 1515/TCP (Enrollment)
                                             |
                                             v
+---------------------------------------------------------------------------------------+
| WAZUH CENTRAL SERVER: ec2-user / wazuh-server (172.31.7.137) - RHEL 9.8               |
|                                                                                       |
|  wazuh-remoted (1514/TCP) & wazuh-authd (1515/TCP)                                    |
|        |                                                                              |
|        v                                                                              |
|  wazuh-analysisd                                                                      |
|   |-- Custom Decoders: /var/ossec/etc/decoders/sftp_decoders.xml                      |
|   |-- Custom Rules:    /var/ossec/etc/rules/sftp_and_vnc_rules.xml                    |
|   |                    /var/ossec/etc/rules/ssh_and_network_rules.xml                 |
|        |                                                                              |
|        +----------------------------+-------------------------------+                 |
|        |                            |                               |                 |
|        v                            v                               v                 |
|  /var/ossec/logs/alerts/     wazuh-apid (55000/TCP)        wazuh-integratord          |
|  alerts.json                        |                               |                 |
|        |                            |                               v                 |
|        v                            |                     custom-html-email.py        |
|  Filebeat (9200/TCP mTLS)           |                      |-- Policy JSON Filter     |
|        |                            |                      |-- fcntl Lock & Dedup     |
|        v                            v                      |-- PID -> User Cache      |
|  wazuh-indexer (9200/TCP) <---> wazuh-dashboard (443/TCP)           |                 |
|  (OpenSearch + Internal Users)  (Admin: admin, Analyst: jakir,      v                 |
|                                  Viewer: viewuser)         Postfix (127.0.0.1:25)     |
+---------------------------------------------------------------------|-----------------+
                                                                      |
                                                       587/TCP (STARTTLS + SASL Auth)
                                                                      |
                                                                      v
                                                        smtp.gmail.com (devops.jakir@gmail.com)
                                                                      |
                                                                      v
                                                        Alert Inbox (hiddenclue0@gmail.com)
```

---

## 2. Prerequisites and Server Planning

### 2.1 Hardware and Operating System Requirements

| Server Role | IP Address | OS | Minimum CPU / RAM | Recommended Root Storage (`/`) | Swap Space |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Wazuh Central Server** | `172.31.7.137` | RHEL 9.8 (`x86_64`) | 4 vCPU / 8 GiB RAM | **100 GB GP3 EBS** (Minimum 50 GB free) | **4 GB `/swapfile`** |
| **Wazuh Agent (`vnc-server`)** | `172.31.9.50` | RHEL 9.8 (`x86_64`) | 4 vCPU / 8 GiB RAM | 50 GB+ GP3 EBS | 2–4 GB Swap |

### 2.2 Required Network & Firewall Ports

| Server | Port | Protocol | Source | Service / Purpose |
| :--- | :--- | :--- | :--- | :--- |
| **Wazuh Central Server (`172.31.7.137`)** | `443` | TCP | Admin / Analyst IPs | Wazuh Dashboard Web UI (HTTPS) |
| **Wazuh Central Server (`172.31.7.137`)** | `1514` | TCP | `172.31.9.50/32` (Agents) | Wazuh Agent encrypted event stream (`wazuh-remoted`) |
| **Wazuh Central Server (`172.31.7.137`)** | `1515` | TCP | `172.31.9.50/32` (Agents) | Wazuh Agent registration (`wazuh-authd`) |
| **Wazuh Central Server (`172.31.7.137`)** | `55000` | TCP | `127.0.0.1` / Admin IPs | Wazuh Server REST API (`wazuh-apid`) |
| **Wazuh Central Server (`172.31.7.137`)** | `9200` | TCP | `127.0.0.1` | Wazuh Indexer REST API (OpenSearch) |
| **Monitored Agent (`172.31.9.50`)** | `22` | TCP | Authorized Clients | OpenSSH & SFTP |
| **Monitored Agent (`172.31.9.50`)** | `5901–5904` | TCP | Authorized Clients | TigerVNC Displays `:1` through `:4` |

---

## 3. Environment Variables and Placeholders

Export this environment variable block in your root shell before running setup commands on either server. Replace `<GMAIL_APP_PASSWORD>`, `<LINUX_USERNAME>`, `<LINUX_GROUP>`, and `<VNC_DISPLAY_NUMBER>` when performing user-specific or SMTP credential steps.

```bash
# ============================================================================
# ENVIRONMENT VARIABLES - REPLACE THESE VALUES FOR YOUR ENVIRONMENT
# ============================================================================

# Wazuh Manager Server
WAZUH_MANAGER_IP="172.31.7.137"                        # e.g., 172.31.15.207
WAZUH_MANAGER_HOSTNAME="ec2-user"                      # e.g., wazuh-server

# Monitored Linux / VNC / SFTP Agent Server
WAZUH_AGENT_IP="172.31.9.50"                           # e.g., 172.31.15.62
WAZUH_AGENT_NAME="vnc-server"                          # e.g., vnc-server
SERVER_HOSTNAME="vnc-server"                           # e.g., vnc-server
SERVER_PRIVATE_IP="172.31.9.50"                        # e.g., 172.31.15.62

# Linux & VNC User Placeholders
LINUX_USERNAME="<LINUX_USERNAME>"                      # e.g., user1, user2, user3, user4
LINUX_GROUP="<LINUX_GROUP>"                            # e.g., sftp-allowed or sftp-denied
VNC_DISPLAY="<VNC_DISPLAY_NUMBER>"                     # e.g., :1, :2, :3, :4

# Postfix Gmail SMTP Relay Placeholders
SMTP_HOST="smtp.gmail.com"
SMTP_PORT="587"
SMTP_USERNAME="devops.jakir@gmail.com"                 # Sender Gmail address
SMTP_APP_PASSWORD="<GMAIL_APP_PASSWORD>"               # 16-character Google App Password
ALERT_RECIPIENT_EMAIL="hiddenclue0@gmail.com"          # Destination email address for alerts

# Wazuh Dashboard Team Account Placeholders
WAZUH_ADMIN_USERNAME="admin"                           # Full administrative user
WAZUH_ANALYST_USERNAME="jakir"                         # Security analyst user
WAZUH_VIEWER_USERNAME="viewuser"                       # Read-only auditor/viewer user
```

---

## 4. Fresh Wazuh Server Installation (From Scratch on `172.31.7.137`)

This section documents the complete installation of **Wazuh Indexer**, **Wazuh Manager**, **Filebeat**, and **Wazuh Dashboard** (`v4.14.9`) on a fresh RHEL 9.8 server (`172.31.7.137`).

### 4.1 Operating System Preparation, Swap, Kernel Tuning, and Disk Expansion

* **Location:** Wazuh Manager (`172.31.7.137`)
* **Execution user:** `root`
* **Purpose:** Upgrade base OS packages, expand the root filesystem, create a 4 GB swap file, and tune OpenSearch kernel memory parameters.

```bash
# 1. Update all RHEL 9.8 packages
dnf clean all
dnf makecache
dnf upgrade -y

# 2. Expand root partition if underlying AWS EBS volume was resized (e.g., to 100 GB)
dnf install -y cloud-utils-growpart
growpart /dev/nvme0n1 4 || true
xfs_growfs /

# 3. Create and enable a persistent 4 GB Swap file
if ! swapon --show | grep -q '/swapfile'; then
    fallocate -l 4G /swapfile
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    grep -q '^/swapfile ' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi

# 4. Configure required kernel parameters for Wazuh Indexer (OpenSearch)
cat << 'EOF' > /etc/sysctl.d/99-wazuh.conf
vm.max_map_count=262144
vm.swappiness=10
EOF
sysctl --system
```

* **Validation:**
```bash
df -h /
free -m
sysctl vm.max_map_count
```
* **Expected output (reference only):**
```text
/dev/nvme0n1p4   99G  2.5G   97G   3% /
Swap:           4095         0      4095
vm.max_map_count = 262144
```

### 4.2 Install Required Packages, Configure DNF Timeouts, and Open Firewall Ports

* **Location:** Wazuh Manager (`172.31.7.137`)
* **Execution user:** `root`
* **Purpose:** Install required shared libraries for the Indexer, Manager, and Dashboard, configure DNF network resiliency, and open ports `443`, `1514`, `1515`, and `55000` in `firewalld`.

```bash
# 1. Increase DNF timeout so large RPM downloads (wazuh-indexer 836MB, wazuh-dashboard 286MB) never abort
grep -q '^timeout=' /etc/dnf/dnf.conf || cat << 'EOF' >> /etc/dnf/dnf.conf
timeout=300
retries=10
minrate=1000
EOF

# 2. Install required OS packages and shared libraries
dnf install -y curl tar coreutils gnupg2 lsof libcap fontconfig nss openssl-libs policycoreutils-python-utils firewalld

# 3. Enable firewalld and open required Wazuh server ports
systemctl enable --now firewalld
firewall-cmd --permanent --add-port={443/tcp,1514/tcp,1515/tcp,55000/tcp}
firewall-cmd --reload
```

* **Validation:**
```bash
rpm -q curl tar lsof libcap fontconfig nss openssl-libs
firewall-cmd --list-ports
```
* **Expected output (reference only):**
```text
443/tcp 1514/tcp 1515/tcp 55000/tcp
```

### 4.3 Add the Official Wazuh 4.x YUM Repository

* **Location:** Wazuh Manager (`172.31.7.137`)
* **Execution user:** `root`
* **Purpose:** Import the Wazuh GPG signing key and configure `/etc/yum.repos.d/wazuh.repo`.

```bash
rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH

cat << 'EOF' > /etc/yum.repos.d/wazuh.repo
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
EOF

dnf makecache
```

* **Validation:**
```bash
dnf repolist --enabled | grep wazuh
```
* **Expected output (reference only):**
```text
wazuh                         EL-9 - Wazuh
```

### 4.4 Generate SSL Certificates and Install Wazuh Indexer, Manager, Filebeat, and Dashboard

You can install the complete Wazuh v4.14.9 stack using the official Wazuh installation assistant step-by-step (which generates `wazuh-install-files.tar` containing all root CA, node SSL certificates, and random passwords, and installs each component without risking a full rollback if a network blip occurs).

* **Location:** Wazuh Manager (`172.31.7.137`)
* **Execution user:** `root`
* **Purpose:** Generate X.509 certificates, install and initialize Wazuh Indexer, install Wazuh Manager and Filebeat, and install Wazuh Dashboard.

```bash
cd /root
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
curl -sO https://packages.wazuh.com/4.14/config.yml
chmod 700 /root/wazuh-install.sh

# 1. Configure single-node IP topology in config.yml
cat << 'EOF' > /root/config.yml
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

# 2. Generate SSL certificates and passwords archive (/root/wazuh-install-files.tar)
bash /root/wazuh-install.sh --generate-config-files

# 3. Install and start Wazuh Indexer
bash /root/wazuh-install.sh --wazuh-indexer node-1 --ignore-check

# 4. Initialize the Wazuh Indexer OpenSearch security cluster and internal users
bash /root/wazuh-install.sh --start-cluster

# 5. Install and start Wazuh Server (wazuh-manager + filebeat)
bash /root/wazuh-install.sh --wazuh-server wazuh-1 --ignore-check

# 6. Install and start Wazuh Dashboard (port 443/TCP)
bash /root/wazuh-install.sh --wazuh-dashboard dashboard --ignore-check

# 7. Back up the generated certificates and passwords archive and lock repo auto-updates
cp -a /root/wazuh-install-files.tar /root/wazuh-install-files-backup.tar
chmod 600 /root/wazuh-install-files.tar /root/wazuh-install-files-backup.tar
sed -i "s/^enabled=1/enabled=0/" /etc/yum.repos.d/wazuh.repo
```

*(Note: Alternatively, `bash /root/wazuh-install.sh -a -i -v` runs steps 1–6 in a single command.)*

### 4.5 Complete Wazuh Central Server Installation Validation

* **Location:** Wazuh Manager (`172.31.7.137`)
* **Execution user:** `root`
* **Purpose:** Verify all four services, retrieve the initial `admin` password, validate Indexer cluster health (`9200`), Manager API (`55000`), and Dashboard HTTPS (`443`).

```bash
# 1. Verify systemd status of all four Wazuh server components
systemctl is-active wazuh-indexer wazuh-manager filebeat wazuh-dashboard

# 2. Extract and display the generated 'admin' password (store securely)
ADMIN_PASS=$(tar -axf /root/wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt -O | awk '/indexer_username:[[:space:]]*'\''admin'\''/{getline; print $2}' | tr -d "'")
echo "Wazuh Admin Username: admin"
echo "Wazuh Admin Password: ${ADMIN_PASS}"

# 3. Verify Wazuh Indexer API and Cluster Health (Port 9200)
curl -sk -u "admin:${ADMIN_PASS}" https://127.0.0.1:9200/_cluster/health?pretty

# 4. Verify Filebeat-to-Indexer TLS connectivity
filebeat test output

# 5. Verify Wazuh Manager API (Port 55000) and Dashboard HTTPS listener (Port 443)
ss -lntp | grep -E ':(443|1514|1515|9200|55000)\b'
curl -skI https://127.0.0.1:443/app/login | head -n 5
```

* **Expected output (reference only):**
```text
active
active
active
active
{
  "cluster_name" : "wazuh-cluster",
  "status" : "green",
  "number_of_nodes" : 1,
  "number_of_data_nodes" : 1
}
talk to server... OK
HTTP/1.1 200 OK
```

---

## 5. Wazuh Agent Installation (RHEL 9.8 and Compatible Linux Servers)

This section provides the complete procedure to install `wazuh-agent-4.14.9-1` on any RHEL 9.8 server (including `vnc-server` at `172.31.9.50`).

### 5.1 Configure the Wazuh Repository and Install the Wazuh Agent

* **Location:** Wazuh Agent (`vnc-server` — `172.31.9.50`)
* **Execution user:** `root`
* **Purpose:** Add the Wazuh repository, install `wazuh-agent-4.14.9-1` configured with Manager IP `172.31.7.137` and agent name `vnc-server`, and disable automatic repo updates.

```bash
WAZUH_MANAGER_IP="172.31.7.137"
WAZUH_AGENT_NAME="vnc-server"

# 1. Import the Wazuh GPG key and configure the repository
rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH

cat << 'EOF' > /etc/yum.repos.d/wazuh.repo
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
EOF

# 2. Install Wazuh Agent v4.14.9 with Manager IP and Agent Name pre-configured
WAZUH_MANAGER="${WAZUH_MANAGER_IP}" WAZUH_AGENT_NAME="${WAZUH_AGENT_NAME}" dnf install -y wazuh-agent-4.14.9-1

# 3. Disable repository auto-updates to keep agent version locked with the manager
sed -i "s/^enabled=1/enabled=0/" /etc/yum.repos.d/wazuh.repo

# 4. Set logcollector polling interval to 1 second for near-real-time event forwarding
grep -q "logcollector.loop_timeout" /var/ossec/etc/local_internal_options.conf || \
    echo "logcollector.loop_timeout=1" >> /var/ossec/etc/local_internal_options.conf
```

* **Validation:**
```bash
rpm -q wazuh-agent
grep -E "<address>|<enrollment>" -A 2 /var/ossec/etc/ossec.conf
```
* **Expected output (reference only):**
```text
wazuh-agent-4.14.9-1.x86_64
      <address>172.31.7.137</address>
```

---

## 6. Agent Registration and Connectivity Verification

### 6.1 Verify Firewall Connectivity and Start the Wazuh Agent

* **Location:** Wazuh Agent (`vnc-server` — `172.31.9.50`)
* **Execution user:** `root`
* **Purpose:** Verify outbound TCP connectivity to `172.31.7.137` on ports `1514` and `1515`, then enable and start `wazuh-agent`.

```bash
WAZUH_MANAGER_IP="172.31.7.137"

# 1. Test TCP connectivity to Wazuh Manager ports 1514 (events) and 1515 (enrollment)
timeout 3 bash -c "</dev/tcp/${WAZUH_MANAGER_IP}/1514 && echo 'Port 1514/TCP: REACHABLE'"
timeout 3 bash -c "</dev/tcp/${WAZUH_MANAGER_IP}/1515 && echo 'Port 1515/TCP: REACHABLE'"

# 2. Enable and start wazuh-agent
systemctl daemon-reload
systemctl enable --now wazuh-agent
sleep 5

# 3. Verify key enrollment and server connection in Agent log
systemctl status wazuh-agent --no-pager
ls -l /var/ossec/etc/client.keys
grep -E "Valid key received|Connected to the server" /var/ossec/logs/ossec.log | tail -n 5
```

* **Expected output (reference only):**
```text
Port 1514/TCP: REACHABLE
Port 1515/TCP: REACHABLE
wazuh-agentd: INFO: Valid key received
wazuh-agentd: INFO: Connected to the server ([172.31.7.137]:1514/tcp).
```

### 6.2 Verify Agent Registration on the Wazuh Manager

* **Location:** Wazuh Manager (`172.31.7.137`)
* **Execution user:** `root`
* **Purpose:** Confirm that `vnc-server` (`172.31.9.50`) is registered and `Active`.

```bash
/var/ossec/bin/agent_control -l
/var/ossec/bin/agent_control -i 001
```

* **Expected output (reference only):**
```text
Wazuh agent_control. List of available agents:
   ID: 000, Name: ec2-user (server), IP: 127.0.0.1, Active/Local
   ID: 001, Name: vnc-server, IP: any, Active
```

---

## 7. Integrating Your Existing RHEL 9.8 TigerVNC & SFTP Server (`172.31.9.50`)

Your `vnc-server` (`172.31.9.50`) already runs GNOME, TigerVNC (`:1=user1`, `:2=user2`, `:3=user3`, `:4=user4`), SELinux in `Enforcing` mode, `firewalld`, and SFTP chroot directories (`/srv/sftp/user1/files`, `/srv/sftp/user2/files`) with groups `sftp-allowed` (`user1`, `user2`) and `sftp-denied` (`user3`, `user4`).

Do **not** reinstall GNOME, TigerVNC, or recreate existing users. Instead, back up your existing configuration files and configure `/var/ossec/etc/ossec.conf` on `vnc-server` so all log sources are collected without duplicate `journald` ingestion.

### 7.1 Back Up Existing Agent Server Configurations

* **Location:** Wazuh Agent (`vnc-server` — `172.31.9.50`)
* **Execution user:** `root`
* **Purpose:** Back up existing SSHD, Auditd, TigerVNC, and Wazuh Agent configurations before applying monitoring integration.

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

### 7.2 Deploy Clean `/var/ossec/etc/ossec.conf` on `vnc-server` (`172.31.9.50`)

**Why This Step Is Essential:** The default Wazuh 4.14 agent config on RHEL 9 includes `<location>journald</location>` at the bottom. If `<location>/var/log/secure</location>` is also added without removing `journald`, every SSH and SFTP event is sent to the Wazuh Manager **twice**, causing duplicate alerts and false brute-force counts.

* **Location:** Wazuh Agent (`vnc-server` — `172.31.9.50`)
* **Execution user:** `root`
* **Purpose:** Configure non-duplicated log collection (`/var/log/secure`, `/var/log/audit/audit.log`, `/var/log/messages`, and TigerVNC logs) and real-time Whodata FIM.

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
systemctl restart wazuh-agent
```

* **Validation:**
```bash
grep "Analyzing file" /var/ossec/logs/ossec.log | tail -n 10
```

---

## 8. Linux User Monitoring (Existing and Newly Created Accounts)

To monitor every Linux account (`ec2-user`, `user1`–`user4`, and any future employee account created with `useradd`) without hardcoding usernames, configure kernel `auditd` rules on `vnc-server` (`172.31.9.50`).

### 8.1 Configure Kernel `auditd` Rules on `vnc-server` (`172.31.9.50`)

* **Location:** Wazuh Agent (`vnc-server` — `172.31.9.50`)
* **Execution user:** `root`
* **Purpose:** Track all commands executed by any human user (`auid >= 1000`), user account creation/deletion, group membership changes, SSHD edits, and TigerVNC config edits.

```bash
dnf install -y audit
systemctl enable --now auditd

rm -f /etc/audit/rules.d/wazuh-command-audit.rules
mkdir -p /etc/tigervnc /etc/firewalld /etc/NetworkManager/system-connections /etc/ssh/sshd_config.d

cat << 'EOF' > /etc/audit/rules.d/wazuh-full-monitoring.rules
-D
-b 8192

## 1. Track all commands executed by any human user (auid >= 1000) including root escalation
-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=-1 -k audit-wazuh-c
-a always,exit -F arch=b32 -S execve -F auid>=1000 -F auid!=-1 -k audit-wazuh-c

## 2. Track user creation, modification, deletion, and password changes
-w /etc/passwd -p wa -k user-modify
-w /etc/shadow -p wa -k user-modify
-w /etc/security/opasswd -p wa -k user-modify

## 3. Track group creation and membership changes (sftp-allowed / sftp-denied)
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

* **Validation:**
```bash
auditctl -l
```
* **Expected output (reference only):**
```text
-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=-1 -F key=audit-wazuh-c
-a always,exit -F arch=b32 -S execve -F auid>=1000 -F auid!=-1 -F key=audit-wazuh-c
-w /etc/passwd -p wa -k user-modify
...
```

---

## 9. SSH Monitoring Configuration

### 9.1 Fix `/etc/ssh/sshd_config.d/40-sftp-access.conf` for Complete SSH & SFTP Visibility

In your previous setup on `vnc-server` (`172.31.9.50`), `/etc/ssh/sshd_config.d/40-sftp-access.conf` had three issues:
1. `LogLevel VERBOSE` was missing.
2. `ForceCommand internal-sftp` did not include `-f AUTHPRIV -l INFO`, so `internal-sftp` never logged file opens, closes, or deletions.
3. `DenyGroups sftp-denied` and `PasswordAuthentication no` under `Match Group sftp-denied` rejected `user3` and `user4` before a password prompt could occur. By removing `DenyGroups` and setting `PasswordAuthentication yes` + `ForceCommand /usr/sbin/nologin` under `Match Group sftp-denied`, `user3` and `user4` remain completely blocked from SSH and SFTP, while both password brute-force attempts (`Failed password`) and unauthorized SFTP attempts (`forced-command (config) '/usr/sbin/nologin' for user3`) are logged with the exact username and source IP!

* **Location:** Wazuh Agent (`vnc-server` — `172.31.9.50`)
* **Execution user:** `root`
* **Purpose:** Configure verbose SSH/SFTP logging for all users, chroot SFTP for `sftp-allowed`, and audited SFTP/SSH denial for `sftp-denied`.

```bash
rm -f /etc/ssh/sshd_config.d/50-sftp-monitoring.conf
sed -i 's/^[[:space:]]*Subsystem[[:space:]]\+sftp/#Subsystem sftp/g' /etc/ssh/sshd_config

cat << 'EOF' > /etc/ssh/sshd_config.d/40-sftp-access.conf
LogLevel VERBOSE
SyslogFacility AUTHPRIV
PasswordAuthentication yes
KbdInteractiveAuthentication yes
Subsystem sftp internal-sftp -f AUTHPRIV -l INFO -u 0022

Match Group sftp-allowed
    PasswordAuthentication yes
    ChrootDirectory /srv/sftp/%u
    ForceCommand internal-sftp -f AUTHPRIV -l INFO -u 0022
    AllowTcpForwarding no
    X11Forwarding no
    PermitTTY no

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
sshd -T -C user=user1,host=localhost,addr=127.0.0.1 | grep -E '^(loglevel|chrootdirectory|forcecommand)'
sshd -T -C user=user3,host=localhost,addr=127.0.0.1 | grep -E '^(loglevel|chrootdirectory|forcecommand|passwordauthentication)'
```
* **Expected output (reference only):**
```text
loglevel VERBOSE
forcecommand internal-sftp -f AUTHPRIV -l INFO -u 0022
chrootdirectory /srv/sftp/%u
loglevel VERBOSE
passwordauthentication yes
forcecommand /usr/sbin/nologin
chrootdirectory none
```

---

## 10. SFTP Monitoring (Chroot `/dev/log` Socket & Automatic New User Provisioning)

### 10.1 Why Chrooted SFTP Users (`user1`, `user2`) Require `/srv/sftp/<user>/dev/log`

When OpenSSH chroots `user1` into `/srv/sftp/user1`, the `internal-sftp` process can no longer reach the host's `/dev/log` socket unless `/run/systemd/journal/dev-log` is bind-mounted at `/srv/sftp/user1/dev/log`.

### 10.2 Configure Chroot `/dev/log` Sockets for Existing Users (`user1`, `user2`) and Create Helper Script for Future Users

* **Location:** Wazuh Agent (`vnc-server` — `172.31.9.50`)
* **Execution user:** `root`
* **Purpose:** Bind-mount `/run/systemd/journal/dev-log` into `/srv/sftp/user1/dev/log` and `/srv/sftp/user2/dev/log`, and create `/usr/local/sbin/setup-sftp-chroot-user.sh` for future `sftp-allowed` accounts.

```bash
# 1. Create reusable helper script for any existing or future sftp-allowed user
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
echo "Configured chroot SFTP and /dev/log socket for ${USERNAME}."
EOF

chmod 750 /usr/local/sbin/setup-sftp-chroot-user.sh

# 2. Apply to existing sftp-allowed users (user1 and user2)
/usr/local/sbin/setup-sftp-chroot-user.sh user1
/usr/local/sbin/setup-sftp-chroot-user.sh user2
systemctl restart rsyslog
```

* **Validation:**
```bash
grep "/srv/sftp" /proc/mounts
```
* **Expected output (reference only):**
```text
/dev/nvme0n1p4 /srv/sftp/user1/dev/log xfs rw,seclabel,relatime,attr2,inode64,logbufs=8,logbsize=32k,prjquota 0 0
/dev/nvme0n1p4 /srv/sftp/user2/dev/log xfs rw,seclabel,relatime,attr2,inode64,logbufs=8,logbsize=32k,prjquota 0 0
```

---

## 11. TigerVNC Monitoring

### 11.1 How TigerVNC Logs Sessions on RHEL 9.8

On RHEL 9.8 (`tigervnc-server-1.15`), each user's `Xvnc` process writes connection and authentication events to `/home/<user>/.local/share/tigervnc/<hostname>:<display>.log`:
* `Connections: accepted: <CLIENT_IP>::<PORT>`
* `Connections: closed: <CLIENT_IP>::<PORT> (AuthFailureException: Authentication failure)`
* `Connections: closed: <CLIENT_IP>::<PORT> (Clean disconnection)`

Because `/var/ossec/etc/ossec.conf` on `vnc-server` (`Section 7.2`) collects `/home/*/.local/share/tigervnc/*.log`, Wazuh receives the log line along with the file path (`location`), allowing our integration script to identify both the **Linux username (`user1`–`user4`)** and **VNC display (`:1`–`:4`)** automatically.

* **Location:** Wazuh Agent (`vnc-server` — `172.31.9.50`)
* **Execution user:** `root`
* **Purpose:** Verify that TigerVNC log files are being monitored by `wazuh-logcollector`.

```bash
ls -la /home/*/.local/share/tigervnc/*.log 2>/dev/null || ls -la /home/*/.vnc/*.log 2>/dev/null
grep -E "tigervnc|\.vnc" /var/ossec/logs/ossec.log
```

---

## 12. Custom Decoders and Rules

### 12.1 Deploy Custom PCRE2 Decoders (`/var/ossec/etc/decoders/sftp_decoders.xml`)

* **Location:** Wazuh Manager (`172.31.7.137`)
* **Execution user:** `root`
* **Purpose:** Decode OpenSSH `internal-sftp` sessions, file `open`, file `close` (bytes read/written), file delete/rename, `forced-command` denials, and TigerVNC `Xvnc` logs.

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

### 12.2 Deploy Custom SFTP and TigerVNC Rules (`/var/ossec/etc/rules/sftp_and_vnc_rules.xml`)

* **Location:** Wazuh Manager (`172.31.7.137`)
* **Execution user:** `root`
* **Purpose:** Create rules for SFTP session open/close (`100501`, `100511`), file open tracking (`100502`, `100503`), authoritative transfer completion (`100507`), file delete/rename (`100504`), unauthorized SFTP denial (`100505`), permission failure (`100508`), and TigerVNC activity (`100506`, `100509`, `100510`, `100513`).

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
/var/ossec/bin/wazuh-analysisd -t
```

---

## 13. Brute-Force Detection (5-Attempt Medium & 10-Attempt High Correlation)

### 13.1 How the Two-Tier Brute-Force Rules Work

* **Rule `100611` (High Severity — Level 12, `frequency="10"`, `timeframe="300"`):** Placed **before** Rule `100601` in `/var/ossec/etc/rules/ssh_and_network_rules.xml` so that when the 10th failed login within 5 minutes arrives, Wazuh evaluates and triggers the High-severity escalation rule first.
* **Rule `100601` (Medium Severity — Level 8, `frequency="5"`, `timeframe="300"`):** Includes `authentication_failed` in its `<group>` list so that attempt #5 triggers the Medium alert while attempts #5–#9 remain in the `authentication_failed` correlation group for Rule `100611`.

### 13.2 Deploy `/var/ossec/etc/rules/ssh_and_network_rules.xml`

* **Location:** Wazuh Manager (`172.31.7.137`)
* **Execution user:** `root`
* **Purpose:** Configure 5-attempt Medium and 10-attempt High SSH brute-force detection, suspicious SSH login rules, user/group modification alerts, and network socket rules.

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
/var/ossec/bin/wazuh-analysisd -t
```

---

## 14. Email Notification Management Policy

### 14.1 Create `/var/ossec/etc/email_notification_policy.json`

* **Location:** Wazuh Manager (`172.31.7.137`)
* **Execution user:** `root`
* **Purpose:** Enable emails by default only for SFTP file transfers (`sftp_successful_transfers`), SFTP denied/failed operations (`sftp_failed_denied_operations`), and SSH brute-force detection (`ssh_bruteforce_detection`), while keeping all other categories configurable.

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

---

## 15. Postfix and Gmail SMTP Setup

Configure Postfix on the Wazuh Manager (`172.31.7.137`) to relay alert emails via `smtp.gmail.com:587` using `devops.jakir@gmail.com` and a 16-character Google App Password.

### 15.1 Install and Configure Postfix STARTTLS Relay

* **Location:** Wazuh Manager (`172.31.7.137`)
* **Execution user:** `root`
* **Purpose:** Install Postfix and SASL modules, configure Gmail STARTTLS relay over IPv4, and test email delivery to `hiddenclue0@gmail.com`.

```bash
SMTP_HOST="smtp.gmail.com"
SMTP_PORT="587"
SMTP_USERNAME="devops.jakir@gmail.com"
SMTP_APP_PASSWORD="<GMAIL_APP_PASSWORD>"
ALERT_RECIPIENT_EMAIL="hiddenclue0@gmail.com"

# 1. Install Postfix, Cyrus SASL, and s-nail
dnf install -y postfix cyrus-sasl cyrus-sasl-plain s-nail
systemctl enable --now postfix

# 2. Configure Postfix parameters idempotently via postconf
postconf -e "inet_protocols = ipv4"
postconf -e "relayhost = [${SMTP_HOST}]:${SMTP_PORT}"
postconf -e "smtp_use_tls = yes"
postconf -e "smtp_sasl_auth_enable = yes"
postconf -e "smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd"
postconf -e "smtp_sasl_security_options = noanonymous"
postconf -e "smtp_tls_security_level = encrypt"
postconf -e "smtp_tls_cafile = /etc/ssl/certs/ca-bundle.crt"

# 3. Create /etc/postfix/sasl_passwd and compile the hash database
cat << EOF > /etc/postfix/sasl_passwd
[${SMTP_HOST}]:${SMTP_PORT} ${SMTP_USERNAME}:${SMTP_APP_PASSWORD}
EOF

chown root:root /etc/postfix/sasl_passwd
chmod 600 /etc/postfix/sasl_passwd
postmap /etc/postfix/sasl_passwd
chown root:root /etc/postfix/sasl_passwd.db
chmod 600 /etc/postfix/sasl_passwd.db

# 4. Validate and restart Postfix
postfix check && systemctl restart postfix
```

* **Validation:**
```bash
echo "Wazuh Postfix Gmail STARTTLS relay verification" | mail -s "Wazuh SMTP Relay Test" "hiddenclue0@gmail.com"
sleep 4
tail -n 15 /var/log/maillog
```
* **Expected output (reference only):**
```text
postfix/smtp[...]: to=<hiddenclue0@gmail.com>, relay=smtp.gmail.com[...]:587, dsn=2.0.0, status=sent (250 2.0.0 OK ... - gsmtp)
```

---

## 16. Duplicate Notification Prevention & HTML Email Integration

### 16.1 Deploy `/var/ossec/integrations/custom-html-email.py`

* **Location:** Wazuh Manager (`172.31.7.137`)
* **Execution user:** `root`
* **Purpose:** Install the custom HTML notification script with `fcntl.flock` concurrency locking, PID session caching, TigerVNC path user extraction, and incident cooldown deduplication.

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
    if location and ("tigervnc" in location or ".vnc" in location):
        m_vnc = re.search(r"/home/([^/]+)/.*:(\d+)\.log", location)
        if m_vnc:
            dstuser = dstuser or m_vnc.group(1)
            vnc_display = f":{m_vnc.group(2)}"

    if not dstuser and file_path:
        if file_path.startswith("/srv/sftp/"):
            parts = file_path.split("/")
            if len(parts) >= 4 and parts[3]:
                dstuser = parts[3]
        elif file_path.startswith("/home/"):
            parts = file_path.split("/")
            if len(parts) >= 3 and parts[2]:
                dstuser = parts[2]

    if not dstuser:
        m_u = re.search(r"(?:for local user |for invalid user |user=|\bfor )([a-zA-Z0-9_.-]+)", full_log)
        if m_u and m_u.group(1) not in ("from", "port", "id"):
            dstuser = m_u.group(1)
    if not srcip:
        m_ip = re.search(r"from \[?([0-9a-fA-F:.]+)\]?", full_log)
        if m_ip:
            srcip = m_ip.group(1)

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
        agent_ip = agent.get("ip", "172.31.9.50")

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
```

### 16.2 Register the Integration in Manager `/var/ossec/etc/ossec.conf` and Restart `wazuh-manager`

* **Location:** Wazuh Manager (`172.31.7.137`)
* **Execution user:** `root`
* **Purpose:** Disable legacy plain-text `wazuh-maild` (`<email_notification>no</email_notification>`), ensure only one `<integration>` block exists for `custom-html-email.py`, and restart `wazuh-manager`.

```bash
cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak

sed -i 's|<email_notification>yes</email_notification>|<email_notification>no</email_notification>|g' /var/ossec/etc/ossec.conf
sed -i '/<email_alerts>/,/<\/email_alerts>/d' /var/ossec/etc/ossec.conf
sed -i '/<integration>/,/<\/integration>/d' /var/ossec/etc/ossec.conf

sed -i '0,/<\/ossec_config>/s|<\/ossec_config>|  <integration>\n    <name>custom-html-email.py</name>\n    <group>authentication_success,sftp_session,notify_sftp_connect,notify_sftp_transfer,notify_sftp_denied,notify_ssh_bruteforce,notify_ssh_suspicious,notify_user_mgmt,notify_group_mgmt,notify_vnc,notify_fim,notify_other,</group>\n    <alert_format>json</alert_format>\n  </integration>\n\n</ossec_config>|' /var/ossec/etc/ossec.conf

/var/ossec/framework/python/bin/python3 -m py_compile /var/ossec/integrations/custom-html-email.py
/var/ossec/bin/wazuh-analysisd -t && systemctl restart wazuh-manager
```

* **Validation:**
```bash
systemctl status wazuh-manager --no-pager
ps aux | grep wazuh-integratord
```

---

## 17. Dashboard Multi-User and Role Management

### 17.1 Account Types and Role Architecture

| Username Variable | Role Tier | OpenSearch Indexer Role | Wazuh Server API Role | Access Scope |
| :--- | :--- | :--- | :--- | :--- |
| `WAZUH_ADMIN_USERNAME="admin"` | **Administrator** | `all_access` | `administrator` | Full control over rules, decoders, agents, and RBAC |
| `WAZUH_ANALYST_USERNAME="jakir"` | **Security Analyst** | `readall_and_monitor`, `kibana_user` | `readonly`, `agents_read` | Investigate alerts, Threat Hunting, FIM, and reports; cannot modify rules |
| `WAZUH_VIEWER_USERNAME="viewuser"` | **Read-Only Viewer** | `readall`, `kibana_read_only` | `readonly` | View dashboards and security events only |

### 17.2 Step-by-Step Procedure to Create `jakir` (Analyst) and `viewuser` (Viewer)

1. Log in to `https://172.31.7.137` as `admin`.
2. Open the main menu ($\equiv$) -> **Indexer Management** -> **Security** -> **Internal users** -> **Create internal user**:
   * Create user `jakir` with a strong password.
   * Create user `viewuser` with a strong password.
3. Map OpenSearch Indexer Roles (**Indexer Management** -> **Security** -> **Roles**):
   * Select `kibana_user` and `readall_and_monitor` -> **Mapped users** -> **Manage mapping** -> Add `jakir`.
   * Select `kibana_read_only` and `readall` -> **Mapped users** -> **Manage mapping** -> Add `viewuser`.
4. Map Wazuh Server API Roles (**Server Management** -> **Security** -> **Roles mapping** -> **Create Role mapping**):
   * **Role mapping name:** `Security_Team_ReadOnly`
   * **Roles:** `readonly`
   * **Internal users:** `jakir`, `viewuser`
   * Click **Save role mapping**.

---

## 18. End-to-End Testing

Run these tests from an authorized testing machine (such as `172.31.7.137`) targeting `vnc-server` (`172.31.9.50`).

### 18.1 SSH Brute-Force (5 Attempts -> Medium Email; 10 Attempts -> High Email)

* **Location:** Testing Machine (`172.31.7.137`)
* **Purpose:** Trigger 5 failed SSH password attempts (`Rule 100601` — Medium) followed by 5 more failed attempts (`Rule 100611` — High) for `user1` and `user3`.

```bash
# Test 5 failed password attempts for user1 (Triggers 1 [MEDIUM] email on attempt #5):
for i in {1..5}; do
  ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1 user1@172.31.9.50
done

# Continue with attempts #6 through #10 within 5 minutes (Triggers 1 [HIGH] escalation email on attempt #10):
for i in {6..10}; do
  ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1 user1@172.31.9.50
done
```

* **Verification on Wazuh Manager (`172.31.7.137`):**
```bash
grep -E '"id":"100601"|"id":"100611"' /var/ossec/logs/alerts/alerts.json | tail -n 5
tail -n 20 /var/log/maillog
```

### 18.2 SFTP Upload (`user1`), Download (`user2`), and Restricted Denial (`user3`)

* **Location:** Testing Machine (`172.31.7.137`)
* **Purpose:** Validate SFTP file upload (`Rule 100507`), SFTP file download (`Rule 100507`), and restricted user SFTP block (`Rule 100505`).

```bash
# 1. Upload a file as user1 (Triggers 1 [MEDIUM] SFTP File Transfer Detected email for user1)
echo "Semiconductor wafer layout test" > chip_layout_v1.gds
sftp user1@172.31.9.50
# Inside sftp>:
cd files
put chip_layout_v1.gds
exit

# 2. Upload and download a file as user2 (Triggers [MEDIUM] SFTP File Transfer Detected email for user2)
sftp user2@172.31.9.50
# Inside sftp>:
cd files
put chip_layout_v1.gds
get chip_layout_v1.gds downloaded_chip.gds
exit

# 3. Attempt SFTP connection as restricted user3 in sftp-denied (Triggers 1 [HIGH] SFTP Access Denied email for user3)
sftp user3@172.31.9.50
```

* **Verification on Wazuh Manager (`172.31.7.137`):**
```bash
grep -E '"id":"100507"|"id":"100505"' /var/ossec/logs/alerts/alerts.json | tail -n 5
tail -n 20 /var/log/maillog
```

---

## 19. Troubleshooting

| Problem | Diagnostic Command | Root Cause & Fix |
| :--- | :--- | :--- |
| **1. Wazuh agent disconnected** | `/var/ossec/bin/agent_control -i 001` (on Manager) | Confirm TCP ports `1514` and `1515` are open in the AWS EC2 Security Group and `firewalld` on `172.31.7.137`. |
| **2. SFTP upload/download events missing for `user1`/`user2`** | `grep "/srv/sftp" /proc/mounts` (on `172.31.9.50`) | Chrooted `internal-sftp` requires `/srv/sftp/<user>/dev/log` bind-mounted. Run `/usr/local/sbin/setup-sftp-chroot-user.sh user1`. |
| **3. SFTP actions misattributed to `ec2-user`** | Inspect `/var/ossec/integrations/custom-html-email.py` | Ensure `custom-html-email.py` does not use `syscheck.audit.user.name` (`auid`) on SFTP events and uses the PID session cache (`Section 16.1`). |
| **4. Brute-force rule not triggering** | `tail -n 20 /var/log/secure` (on `172.31.9.50`) | Use `ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no` so SSH prompts for a password rather than disconnecting at `[preauth]`. |
| **5. Duplicate emails sent** | `grep "<integration>" /var/ossec/etc/ossec.conf` | Ensure `<email_notification>no</email_notification>` is set, only one `<integration>` block exists, and `journald` is removed from Agent `ossec.conf`. |
| **6. Postfix auth failure (`535 5.7.8`)** | `tail -n 30 /var/log/maillog` (on `172.31.7.137`) | Update `/etc/postfix/sasl_passwd` with a valid 16-character Google App Password, run `postmap /etc/postfix/sasl_passwd`, and restart `postfix`. |

---

## 20. Backup, Recovery, and Employee Maintenance

### 20.1 Onboarding a New Linux / SFTP / TigerVNC Employee Account

* **Location:** Wazuh Agent (`vnc-server` — `172.31.9.50`)
* **Execution user:** `root`
* **Purpose:** Create a new employee account (`<LINUX_USERNAME>`) with automatic SSH, SFTP, and TigerVNC monitoring.

```bash
LINUX_USERNAME="<LINUX_USERNAME>"
VNC_DISPLAY="<VNC_DISPLAY_NUMBER>"   # e.g., :5

# 1. Create Linux user and set password
useradd -m -s /bin/bash "$LINUX_USERNAME"
chmod 700 "/home/${LINUX_USERNAME}"
passwd "$LINUX_USERNAME"

# 2A. If user is allowed SFTP access:
/usr/local/sbin/setup-sftp-chroot-user.sh "$LINUX_USERNAME"

# 2B. OR if user is DENIED SFTP access (VNC-only):
# usermod -aG sftp-denied "$LINUX_USERNAME"

# 3. Configure TigerVNC display:
echo "${VNC_DISPLAY}=${LINUX_USERNAME}" >> /etc/tigervnc/vncserver.users
su - "$LINUX_USERNAME" -c "vncpasswd"
systemctl daemon-reload
systemctl enable --now "vncserver@${VNC_DISPLAY}.service"
systemctl restart wazuh-agent
```

### 20.2 Full Configuration Backup & Rollback Commands

```bash
# Back up Wazuh Manager (172.31.7.137):
tar -czf "/root/wazuh_manager_full_backup_$(date +%Y%m%d).tar.gz" \
  /var/ossec/etc/ossec.conf \
  /var/ossec/etc/decoders/ \
  /var/ossec/etc/rules/ \
  /var/ossec/etc/email_notification_policy.json \
  /var/ossec/integrations/custom-html-email.py \
  /etc/postfix/main.cf /etc/postfix/sasl_passwd

# Roll back Wazuh Manager if needed:
tar -xzf /root/wazuh_manager_full_backup_<DATE>.tar.gz -C /
/var/ossec/bin/wazuh-analysisd -t && systemctl restart wazuh-manager
```
