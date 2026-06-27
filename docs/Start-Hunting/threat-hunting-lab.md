# Building Your First Threat Hunting Lab: A Complete Home Lab Setup Guide

**By a SOC Analyst who's built and burned down more VMs than they care to admit**

Alternative labs you can try from these Github repos: **[Threat Hunting Labs using Docker](https://github.com/pbmundas/Threat-Hunting-Docker-Lab)** and for creating vulnreable machines you can use **[Creating Vulnerable machines using scripts (Ubuntu & Windows)](https://github.com/pbmundas/Purple-Teaming-Lab-for-SOC)**

---

There's a specific kind of frustration that comes with reading about threat hunting in theory attacker persistence via registry run keys, lateral movement through WMI, credential dumping with LSASS and then sitting in front of a production SIEM where you can't actually test anything without your change advisory board needing three weeks' notice and a project code. That gap between knowing what to look for and having a safe place to actually look for it is exactly what a home lab solves.

This guide is for analysts who want a real working environment: not a screenshot walkthrough, not a "spin up this SaaS and call it done," but an actual local lab where you can detonate malware samples, watch Sysmon scream about it, ingest those logs into Elastic, and build detection logic you can later carry into production. Everything here runs on your own hardware. Nothing phones home except for the software packages you pull during setup.

We'll go through the full stack: hypervisor choice, Windows Server and Windows 10 VM setup, Sysmon deployment with a solid config, an Elastic stack running in Docker, log shipping via Winlogbeat, and a practical exercise to verify the whole pipeline is working end to end. By the time you're done, you'll have a lab you can actually use.

---

## What You'll Need Before You Start

Let's get the hardware conversation out of the way first, because this is where a lot of guides are either vague or unrealistic.

**Minimum viable spec:**
- 16 GB RAM (you can squeeze by with 12 but it's not fun)
- A CPU with hardware virtualization support (check BIOS Intel VT-x or AMD-V must be enabled)
- 250 GB free disk space, SSD preferred
- A host OS you're comfortable with Windows 10/11, Ubuntu 22.04, or macOS all work

**Comfortable spec:**
- 32 GB RAM
- 6+ physical cores
- 500 GB SSD

If you're on 8 GB RAM, this lab will technically run but you'll be waiting a lot. The Elastic stack alone wants at least 4 GB. Factor that in.

For software, you'll need:

- **VMware Workstation Pro** (now free for personal use as of 2024) or **VirtualBox 7.x** (free, open source)
- **Windows Server 2022 Evaluation ISO** free 180-day eval from Microsoft
- **Windows 10 Enterprise Evaluation ISO** also free from Microsoft's eval center
- **Docker Desktop** (for running the Elastic stack)
- **Sysmon** from Sysinternals, plus the SwiftOnSecurity or Olaf Hartong config
- **Winlogbeat** for shipping logs

All of this is legally free for lab use. No licenses to buy.

---

## Choosing Your Hypervisor

The VMware vs VirtualBox question comes up every time, and the honest answer is: it depends on what you're optimizing for.

**VMware Workstation Pro** is faster, handles nested virtualization better (important if you later want to run Hyper-V inside a VM), has better USB and network device passthrough, and the snapshot management is cleaner. The downside used to be cost, but Broadcom made it free for personal use. The licensing interface is annoying but the product itself is solid.

**VirtualBox** is open source, runs on everything including Linux hosts without any fuss, has an extensive API, and the community is large. Performance is noticeably lower than VMware for disk I/O intensive workloads which Elastic definitely is but for this lab it's perfectly usable. If you're on Linux and don't want to deal with Broadcom's licensing portal, VirtualBox is the pragmatic choice.

For this guide I'll reference VMware Workstation Pro, but I'll note the VirtualBox equivalent wherever the steps differ meaningfully.

---

## Network Architecture: Why Segmentation Matters from Day One

Before you create a single VM, think about how they're going to talk to each other and more importantly, what they're *not* going to be allowed to reach.

The reason you want network segmentation in a home lab isn't paranoia about your own home network getting infected (though that's a real concern if you're running live malware). It's that segmentation teaches you to think the way enterprise environments are designed, which makes your detection logic more realistic and your understanding of attacker techniques deeper.

Here's the basic topology we're building:

```
[Host Machine]
    |
    ├── NAT Network (Lab-External): 192.168.100.0/24
    |       └── Used for initial setup, updates, pulling packages
    |
    └── Host-Only Network (Lab-Internal): 10.10.10.0/24
            ├── Windows Server 2022 (DC)   10.10.10.10
            ├── Windows 10 Victim VM       10.10.10.20
            └── [Host Machine reaches Elastic via 10.10.10.1]
```

The Elastic stack runs on your host machine in Docker. The victim VMs live on the host-only network and ship logs to the host's IP (10.10.10.1 in VMware's default host-only adapter).

**In VMware:** Go to Edit → Virtual Network Editor. Create VMnet1 as Host-only, subnet 10.10.10.0/24, DHCP disabled. Create VMnet8 as NAT for internet access during setup.

**In VirtualBox:** Tools → Network → Host-only Networks. Create vboxnet0 at 10.10.10.1/24, DHCP off. Use NAT for the second adapter during setup, then disable it once you've finished patching and installing software.

---

## Setting Up Windows Server 2022 as a Domain Controller

You don't strictly need Active Directory for log ingestion, but you want it because:

1. Event logs are dramatically more interesting in a domain environment Kerberos events, Group Policy processing, LDAP queries, all the good stuff
2. Real enterprise environments run AD, so your detection content should be built against AD telemetry
3. It lets you practice Group Policy-based Sysmon deployment, which is how you'll actually roll it out at work

### Creating the VM

In VMware Workstation:

1. File → New Virtual Machine → Custom
2. Choose "I will install the operating system later"
3. Guest OS: Windows Server 2022
4. Name it something sensible: `LAB-DC01`
5. Processors: 2 cores
6. RAM: 4096 MB
7. Network: Host-only (VMnet1 your 10.10.10.0/24 network)
8. Disk: 60 GB, single file
9. After creation, add a second network adapter set to NAT you need this to pull Windows updates and the software you're about to install

Mount the Windows Server 2022 ISO and boot. Go through the installation wizard, pick "Windows Server 2022 Standard (Desktop Experience)" you want the GUI for lab work. Set a strong Administrator password you won't forget. Something like `LabAdmin@2024!` works fine for a local lab.

### Basic Post-Install Configuration

After first boot:

```powershell
# Set the hostname
Rename-Computer -NewName "LAB-DC01" -Restart

# After reboot, set a static IP on the host-only adapter
# Open Network Connections, find the adapter on the 10.10.10.x subnet
# Set: IP 10.10.10.10, Mask 255.255.255.0, Gateway blank, DNS 127.0.0.1
```

### Promoting to Domain Controller

```powershell
# Install AD DS role
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

# Promote to DC - this creates a new forest
Install-ADDSForest `
    -DomainName "lab.local" `
    -DomainNetBiosName "LAB" `
    -ForestMode "WinThreshold" `
    -DomainMode "WinThreshold" `
    -InstallDns:$true `
    -SafeModeAdministratorPassword (ConvertTo-SecureString "LabAdmin@2024!" -AsPlainText -Force) `
    -Force:$true
```

The server will reboot. After it comes back up, you have a functioning domain controller. Create a few test user accounts you'll need them for realistic log generation:

```powershell
# Create some test users
$password = ConvertTo-SecureString "User@2024!" -AsPlainText -Force

New-ADUser -Name "Alice Smith" -SamAccountName "asmith" -UserPrincipalName "asmith@lab.local" `
    -AccountPassword $password -Enabled $true -PasswordNeverExpires $true

New-ADUser -Name "Bob Jones" -SamAccountName "bjones" -UserPrincipalName "bjones@lab.local" `
    -AccountPassword $password -Enabled $true -PasswordNeverExpires $true

# Create a basic OU structure
New-ADOrganizationalUnit -Name "Workstations" -Path "DC=lab,DC=local"
New-ADOrganizationalUnit -Name "Servers" -Path "DC=lab,DC=local"
```

---

## Deploying Sysmon: The Telemetry Foundation

Sysmon is the single most important piece of the lab from a detection perspective. Windows' native event logging is useful but sparse. Sysmon gives you process creation with full command lines and parent process info, network connections with the process that made them, file creation with hashes, registry modifications, DNS queries, pipe creation the full picture that makes detection actually possible.

### Why the Config Matters

Sysmon with default settings generates so much noise it becomes useless. You need a good filter configuration that captures attacker-relevant events while suppressing the background noise of legitimate Windows operations.

Two configs are widely used:

- **SwiftOnSecurity sysmonconfig.xml** conservative, well-maintained, good starting point
- **Olaf Hartong's modular config** more comprehensive, better organized, tuned for ATT&CK coverage

For this lab, we'll use the SwiftOnSecurity config as the base:

### Installing Sysmon on the DC

Download Sysmon from the Microsoft Sysinternals page and grab the SwiftOnSecurity config from GitHub. On your Windows Server VM:

```powershell
# Create a tools directory
New-Item -ItemType Directory -Path "C:\Tools" -Force

# Download Sysmon (adjust the path to where you've saved it)
# If you have internet access on the VM temporarily:
$ProgressPreference = 'SilentlyContinue'
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" `
    -OutFile "C:\Tools\Sysmon.zip"
Expand-Archive -Path "C:\Tools\Sysmon.zip" -DestinationPath "C:\Tools\Sysmon"

# Download the SwiftOnSecurity config
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" `
    -OutFile "C:\Tools\sysmon-config.xml"

# Install Sysmon with the config
C:\Tools\Sysmon\Sysmon64.exe -accepteula -i C:\Tools\sysmon-config.xml
```

Verify it's running:

```powershell
Get-Service Sysmon64
# Should show Status: Running

# Check the event log is being populated
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10 | 
    Select-Object TimeCreated, Id, Message | Format-List
```

If you see events coming in, Sysmon is working. Event ID 1 is process creation you should see a flood of them just from normal system activity.

### What the Key Event IDs Mean

You'll be building detection around these:

| Event ID | What It Captures | Why It Matters |
|----------|-----------------|----------------|
| 1 | Process Create | Command lines, parent-child relationships, hashes |
| 3 | Network Connect | Outbound connections with originating process |
| 7 | Image Loaded | DLL loads catches reflective DLL injection |
| 8 | CreateRemoteThread | Classic injection technique indicator |
| 10 | ProcessAccess | LSASS dumps, process hollowing detection |
| 11 | FileCreate | Dropped payloads, persistence artifacts |
| 12/13 | Registry Events | Run keys, service installs, persistence |
| 15 | FileCreateStreamHash | Alternate data streams |
| 22 | DNS Query | C2 beaconing, domain generation detection |

---

## Setting Up the Windows 10 Victim VM

This is your primary hunting target the endpoint you'll simulate attacks against. Keep it separate from the DC.

### VM Creation

Same process as before, but:
- Name: `LAB-WIN10`
- RAM: 4096 MB
- Disk: 60 GB
- Network: Host-only (10.10.10.0/24)

Install Windows 10 Enterprise Evaluation. After install:

```powershell
# Rename and set static IP
Rename-Computer -NewName "LAB-WIN10" -Restart
```

After reboot, set the static IP on the host-only adapter: 10.10.10.20, mask 255.255.255.0, DNS pointing to 10.10.10.10 (the DC).

### Join the Domain

```powershell
# Join the lab.local domain
Add-Computer -DomainName "lab.local" `
    -Credential (Get-Credential) `  # Use LAB\Administrator
    -OUPath "OU=Workstations,DC=lab,DC=local" `
    -Restart
```

### Install Sysmon on the Workstation

Same process as the DC copy the Sysmon installer and config over (share a folder in VMware or use a Python HTTP server on the host), install with the same config.

### Enable Additional Windows Audit Policy

Sysmon is great but you also want native Windows audit events. These live in the Security event log and cover authentication events (4624, 4625, 4648, 4768, 4769), account management, and policy changes.

```powershell
# Enable comprehensive audit policy
# Process creation with command line (critical for detection)
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable

# Logon events
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable /failure:enable
auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable

# Account management
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable

# Object access
auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:enable

# Enable command line logging in process creation events
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
    -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord -Force

# Also enable PowerShell Script Block Logging
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
    -Name "EnableScriptBlockLogging" -Value 1 -Type DWord

# And Module Logging
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" `
    -Name "EnableModuleLogging" -Value 1 -Type DWord
```

These registry keys enable the same logging you'd apply via Group Policy in production. In the lab, direct registry edits are faster.

---

## The Elastic Stack: Your SIEM Backend

The Elastic Stack (Elasticsearch + Kibana + Logstash, or just Elasticsearch + Kibana with Elastic Agent/Beats) is the right choice for a home lab because:

- The free tier (Basic) is generous enough for everything you'll do
- It's what many enterprise SIEMs are built on or are adjacent to
- The query language (KQL and EQL) is worth learning EQL in particular maps well to attacker behavior sequencing
- Elastic Security (the SIEM layer) has built-in detection rules mapped to MITRE ATT&CK

We're running this in Docker because it's the cleanest way to get a reproducible stack that doesn't fight with your host OS's libraries.

---

## The Docker Compose Stack

Here's the complete, production-tested Docker Compose file for the lab. This handles Elasticsearch, Kibana, and Logstash in a single stack with proper configuration, persistent volumes, and health checks.

**Save this as `docker-compose.yml` in a directory called `elastic-lab` on your host machine.**

```yaml
version: '3.8'

services:
  setup:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.13.4
    container_name: elastic-setup
    volumes:
      - certs:/usr/share/elasticsearch/config/certs
    user: "0"
    environment:
      - ELASTIC_PASSWORD=${ELASTIC_PASSWORD}
      - KIBANA_PASSWORD=${KIBANA_PASSWORD}
    command: >
      bash -c '
        if [ x${ELASTIC_PASSWORD} == x ]; then
          echo "Set the ELASTIC_PASSWORD environment variable in the .env file";
          exit 1;
        elif [ x${KIBANA_PASSWORD} == x ]; then
          echo "Set the KIBANA_PASSWORD environment variable in the .env file";
          exit 1;
        fi;
        if [ ! -f config/certs/ca.zip ]; then
          echo "Creating CA";
          bin/elasticsearch-certutil ca --silent --pem -out config/certs/ca.zip;
          unzip config/certs/ca.zip -d config/certs;
        fi;
        if [ ! -f config/certs/certs.zip ]; then
          echo "Creating certs";
          echo -ne \
          "instances:\n"\
          "  - name: elasticsearch\n"\
          "    dns:\n"\
          "      - elasticsearch\n"\
          "      - localhost\n"\
          "    ip:\n"\
          "      - 127.0.0.1\n"\
          "      - 0.0.0.0\n"\
          > config/certs/instances.yml;
          bin/elasticsearch-certutil cert --silent --pem -out config/certs/certs.zip \
            --in config/certs/instances.yml --ca-cert config/certs/ca/ca.crt \
            --ca-key config/certs/ca/ca.key;
          unzip config/certs/certs.zip -d config/certs;
        fi;
        echo "Setting file permissions";
        chown -R root:root config/certs;
        find . -type d -exec chmod 750 \{\} \;;
        find . -type f -exec chmod 640 \{\} \;;
        echo "Waiting for Elasticsearch availability";
        until curl -s --cacert config/certs/ca/ca.crt https://elasticsearch:9200 | grep -q "missing authentication credentials"; do sleep 30; done;
        echo "Setting kibana_system password";
        until curl -s -X POST --cacert config/certs/ca/ca.crt -u "elastic:${ELASTIC_PASSWORD}" \
          -H "Content-Type: application/json" \
          https://elasticsearch:9200/_security/user/kibana_system/_password \
          -d "{\"password\":\"${KIBANA_PASSWORD}\"}" | grep -q "^{}"; do sleep 10; done;
        echo "All done!";
      '
    healthcheck:
      test: ["CMD-SHELL", "[ -f config/certs/elasticsearch/elasticsearch.crt ]"]
      interval: 1s
      timeout: 5s
      retries: 120

  elasticsearch:
    depends_on:
      setup:
        condition: service_healthy
    image: docker.elastic.co/elasticsearch/elasticsearch:8.13.4
    container_name: elasticsearch
    volumes:
      - certs:/usr/share/elasticsearch/config/certs
      - esdata:/usr/share/elasticsearch/data
    ports:
      - "9200:9200"
    environment:
      - node.name=elasticsearch
      - cluster.name=lab-cluster
      - discovery.type=single-node
      - ELASTIC_PASSWORD=${ELASTIC_PASSWORD}
      - bootstrap.memory_lock=true
      - xpack.security.enabled=true
      - xpack.security.http.ssl.enabled=true
      - xpack.security.http.ssl.key=certs/elasticsearch/elasticsearch.key
      - xpack.security.http.ssl.certificate=certs/elasticsearch/elasticsearch.crt
      - xpack.security.http.ssl.certificate_authorities=certs/ca/ca.crt
      - xpack.security.transport.ssl.enabled=true
      - xpack.security.transport.ssl.key=certs/elasticsearch/elasticsearch.key
      - xpack.security.transport.ssl.certificate=certs/elasticsearch/elasticsearch.crt
      - xpack.security.transport.ssl.certificate_authorities=certs/ca/ca.crt
      - xpack.security.transport.ssl.verification_mode=certificate
      - xpack.license.self_generated.type=basic
      - "ES_JAVA_OPTS=-Xms2g -Xmx2g"
    mem_limit: 3g
    ulimits:
      memlock:
        soft: -1
        hard: -1
    healthcheck:
      test:
        [
          "CMD-SHELL",
          "curl -s --cacert config/certs/ca/ca.crt https://localhost:9200 | grep -q 'missing authentication credentials'",
        ]
      interval: 10s
      timeout: 10s
      retries: 120
    restart: unless-stopped

  kibana:
    depends_on:
      elasticsearch:
        condition: service_healthy
    image: docker.elastic.co/kibana/kibana:8.13.4
    container_name: kibana
    volumes:
      - certs:/usr/share/kibana/config/certs
      - kibanadata:/usr/share/kibana/data
    ports:
      - "5601:5601"
    environment:
      - SERVERNAME=kibana
      - ELASTICSEARCH_HOSTS=https://elasticsearch:9200
      - ELASTICSEARCH_USERNAME=kibana_system
      - ELASTICSEARCH_PASSWORD=${KIBANA_PASSWORD}
      - ELASTICSEARCH_SSL_CERTIFICATEAUTHORITIES=config/certs/ca/ca.crt
      - XPACK_SECURITY_ENCRYPTIONKEY=${ENCRYPTION_KEY}
      - XPACK_ENCRYPTEDSAVEDOBJECTS_ENCRYPTIONKEY=${ENCRYPTION_KEY}
      - XPACK_REPORTING_ENCRYPTIONKEY=${ENCRYPTION_KEY}
    mem_limit: 2g
    healthcheck:
      test:
        [
          "CMD-SHELL",
          "curl -s -I http://localhost:5601 | grep -q 'HTTP/1.1 302 Found'",
        ]
      interval: 10s
      timeout: 10s
      retries: 120
    restart: unless-stopped

  logstash:
    depends_on:
      elasticsearch:
        condition: service_healthy
    image: docker.elastic.co/logstash/logstash:8.13.4
    container_name: logstash
    volumes:
      - certs:/usr/share/logstash/config/certs
      - ./logstash/pipeline:/usr/share/logstash/pipeline
      - ./logstash/config/logstash.yml:/usr/share/logstash/config/logstash.yml
    ports:
      - "5044:5044"    # Beats input (Winlogbeat)
      - "5045:5045"    # Syslog input (future use)
      - "9600:9600"    # Logstash API
    environment:
      - ELASTIC_PASSWORD=${ELASTIC_PASSWORD}
      - LS_JAVA_OPTS=-Xms1g -Xmx1g
    mem_limit: 2g
    healthcheck:
      test: ["CMD-SHELL", "curl -s http://localhost:9600 | grep -q 'green'"]
      interval: 30s
      timeout: 15s
      retries: 30
      start_period: 60s
    restart: unless-stopped

volumes:
  certs:
    driver: local
  esdata:
    driver: local
  kibanadata:
    driver: local
```

---

## Supporting Configuration Files

You need a few more files alongside the `docker-compose.yml`. Here's the complete directory structure and each file's content.

### Directory Structure

```
elastic-lab/
├── docker-compose.yml
├── .env
├── logstash/
│   ├── config/
│   │   └── logstash.yml
│   └── pipeline/
│       └── winlogbeat.conf
```

### The .env File

```bash
# elastic-lab/.env
# Change these passwords before running in any environment

ELASTIC_PASSWORD=LabElastic@2024!
KIBANA_PASSWORD=LabKibana@2024!
ENCRYPTION_KEY=a7f3c2b1d8e4f9a0b5c6d7e8f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0
```

### logstash/config/logstash.yml

```yaml
http.host: "0.0.0.0"
xpack.monitoring.enabled: false
```

### logstash/pipeline/winlogbeat.conf

This is the pipeline configuration that receives Winlogbeat data, does some enrichment, and writes to Elasticsearch. This is the part most guides skip over or make too simple.

```ruby
input {
  beats {
    port => 5044
    ssl => false
    # For production, enable SSL here and provide certificates
    # ssl_certificate => "/usr/share/logstash/config/certs/logstash.crt"
    # ssl_key => "/usr/share/logstash/config/certs/logstash.key"
    # ssl_certificate_authorities => ["/usr/share/logstash/config/certs/ca/ca.crt"]
    # ssl_verify_mode => "force_peer"
  }
}

filter {
  # Parse the winlog.event_data fields if they exist
  if [winlog][event_data] {
    ruby {
      code => "
        event_data = event.get('[winlog][event_data]')
        if event_data.is_a?(Hash)
          event_data.each do |k, v|
            event.set('[winlog][event_data][' + k + ']', v) if v
          end
        end
      "
    }
  }

  # Tag Sysmon events by Event ID for easier filtering
  if [winlog][channel] == "Microsoft-Windows-Sysmon/Operational" {
    mutate {
      add_tag => ["sysmon"]
    }

    if [winlog][event_id] == 1 {
      mutate { add_tag => ["process_create"] }
    } else if [winlog][event_id] == 3 {
      mutate { add_tag => ["network_connect"] }
    } else if [winlog][event_id] == 7 {
      mutate { add_tag => ["image_load"] }
    } else if [winlog][event_id] == 8 {
      mutate { add_tag => ["create_remote_thread"] }
    } else if [winlog][event_id] == 10 {
      mutate { add_tag => ["process_access"] }
    } else if [winlog][event_id] == 11 {
      mutate { add_tag => ["file_create"] }
    } else if [winlog][event_id] in [12, 13, 14] {
      mutate { add_tag => ["registry_event"] }
    } else if [winlog][event_id] == 22 {
      mutate { add_tag => ["dns_query"] }
    }
  }

  # Tag Security log events
  if [winlog][channel] == "Security" {
    mutate {
      add_tag => ["windows_security"]
    }

    # Common auth event tagging
    if [winlog][event_id] in [4624, 4625, 4648, 4768, 4769, 4771] {
      mutate { add_tag => ["authentication"] }
    }

    if [winlog][event_id] in [4720, 4722, 4723, 4724, 4725, 4726, 4728, 4729, 4732, 4733] {
      mutate { add_tag => ["account_management"] }
    }
  }

  # Normalize timestamp
  date {
    match => ["[winlog][time_created]", "ISO8601"]
    target => "@timestamp"
  }

  # Add lab source enrichment
  mutate {
    add_field => {
      "[@metadata][index_prefix]" => "lab-winlogbeat"
    }
  }

  # Extract useful fields from Sysmon process create events
  if "process_create" in [tags] {
    if [winlog][event_data][CommandLine] {
      mutate {
        copy => { "[winlog][event_data][CommandLine]" => "[process][command_line]" }
      }
    }
    if [winlog][event_data][Image] {
      mutate {
        copy => { "[winlog][event_data][Image]" => "[process][executable]" }
      }
    }
    if [winlog][event_data][ParentImage] {
      mutate {
        copy => { "[winlog][event_data][ParentImage]" => "[process][parent][executable]" }
      }
    }
    if [winlog][event_data][User] {
      mutate {
        copy => { "[winlog][event_data][User]" => "[user][name]" }
      }
    }
  }
}

output {
  elasticsearch {
    hosts => ["https://elasticsearch:9200"]
    ssl => true
    cacert => "/usr/share/logstash/config/certs/ca/ca.crt"
    user => "elastic"
    password => "${ELASTIC_PASSWORD}"
    index => "%{[@metadata][index_prefix]}-%{+YYYY.MM.dd}"

    # Use ILM for index lifecycle management
    ilm_enabled => true
    ilm_rollover_alias => "lab-winlogbeat"
    ilm_pattern => "{now/d}-000001"
    ilm_policy => "lab-default-policy"
  }

  # Uncomment for debugging prints events to Logstash stdout
  # stdout {
  #   codec => rubydebug
  # }
}
```

---

## Starting the Stack

With all files in place, from your `elastic-lab` directory:

```bash
# First time: pull images and initialize
docker compose up setup

# Wait for setup to complete (it will print "All done!"), then:
docker compose up -d elasticsearch kibana logstash

# Check that everything is healthy
docker compose ps

# Watch the logs during startup
docker compose logs -f elasticsearch
```

Elasticsearch takes 60–90 seconds to fully initialize. Kibana takes another 30–60 seconds after that. Once both are up:

- Kibana UI: `http://localhost:5601`
- Login: `elastic` / `LabElastic@2024!` (from your .env)

Go to Kibana → Stack Management → Index Management to verify the service is ready.

---

## Installing and Configuring Winlogbeat

Winlogbeat is the log shipper that runs on your Windows VMs and sends events to Logstash. Install it on both the DC and the Win10 VM.

On each Windows machine (run PowerShell as Administrator):

```powershell
# Download Winlogbeat 8.13.4
$ProgressPreference = 'SilentlyContinue'
Invoke-WebRequest -Uri "https://artifacts.elastic.co/downloads/beats/winlogbeat/winlogbeat-8.13.4-windows-x86_64.zip" `
    -OutFile "C:\Tools\winlogbeat.zip"

Expand-Archive -Path "C:\Tools\winlogbeat.zip" -DestinationPath "C:\Tools\"
Rename-Item "C:\Tools\winlogbeat-8.13.4-windows-x86_64" "C:\Tools\winlogbeat"
```

Create the Winlogbeat configuration file at `C:\Tools\winlogbeat\winlogbeat.yml`:

```yaml
# winlogbeat.yml Save at C:\Tools\winlogbeat\winlogbeat.yml

winlogbeat.event_logs:
  # Windows Security log authentication, account management, policy changes
  - name: Security
    event_id: 1100, 1102, 4624, 4625, 4634, 4647, 4648, 4657, 4663, 4688,
              4697, 4698, 4699, 4700, 4701, 4702, 4706, 4720, 4722, 4723,
              4724, 4725, 4726, 4728, 4729, 4732, 4733, 4738, 4756, 4757,
              4768, 4769, 4771, 4776, 4778, 4779, 4798, 4799, 4964
    ignore_older: 72h
    processors:
      - add_fields:
          target: ''
          fields:
            log.source: 'windows-security'

  # System log service installs, driver loads, scheduled task activity
  - name: System
    event_id: 7034, 7035, 7036, 7040, 7045
    ignore_older: 72h

  # Application log
  - name: Application
    ignore_older: 72h
    level: error, critical

  # Sysmon the good stuff
  - name: Microsoft-Windows-Sysmon/Operational
    ignore_older: 72h
    processors:
      - add_fields:
          target: ''
          fields:
            log.source: 'sysmon'

  # PowerShell script block logging
  - name: Microsoft-Windows-PowerShell/Operational
    event_id: 4103, 4104, 4105, 4106
    ignore_older: 72h

  # Windows Defender
  - name: Microsoft-Windows-Windows Defender/Operational
    event_id: 1006, 1007, 1008, 1009, 1010, 1116, 1117
    ignore_older: 72h

  # Task Scheduler
  - name: Microsoft-Windows-TaskScheduler/Operational
    event_id: 106, 140, 141, 200, 201
    ignore_older: 72h

# Ship to Logstash
output.logstash:
  hosts: ["10.10.10.1:5044"]   # Your host machine IP on the host-only network
  # For SSL in production, add:
  # ssl.certificate_authorities: ["C:/Tools/certs/ca.crt"]

# Fields added to every event
fields:
  lab.environment: "home-lab"
  lab.version: "1.0"
fields_under_root: true

# Logging configuration
logging.level: info
logging.to_files: true
logging.files:
  path: C:\Tools\winlogbeat\logs
  name: winlogbeat
  keepfiles: 7

# Queue settings for reliability
queue.mem:
  events: 4096
  flush.min_events: 512
  flush.timeout: 5s
```

Install and start the service:

```powershell
# Install as a Windows service
cd C:\Tools\winlogbeat
.\install-service-winlogbeat.ps1

# Start the service
Start-Service winlogbeat

# Verify it's running
Get-Service winlogbeat

# Watch the logs to confirm it's connecting
Get-Content "C:\Tools\winlogbeat\logs\winlogbeat" -Tail 50 -Wait
```

You should see lines like:

```
INFO    [publisher_pipeline_output] pipeline/output.go:143  Connection to backoff(async(tcp://10.10.10.1:5044)) established
```

That means Winlogbeat has connected to your Logstash instance and is shipping events.

---

## Verifying the Complete Pipeline

This is the moment of truth. Log into Kibana at `http://localhost:5601`.

### Check Logstash is Receiving Data

In Kibana, go to Management → Dev Tools and run:

```
GET _cat/indices/lab-winlogbeat*?v&s=index
```

You should see indices appearing with growing document counts. If they're not there yet, wait 60 seconds and try again there's a small delay before the first batch of events is indexed.

### Create an Index Pattern

1. Go to Management → Stack Management → Index Patterns
2. Create index pattern: `lab-winlogbeat-*`
3. Time field: `@timestamp`
4. Save

### Verify in Discover

Go to Analytics → Discover. Select the `lab-winlogbeat-*` index pattern. Set the time range to "Last 15 minutes." You should see a stream of events from your Windows VMs.

Filter to just Sysmon events:

```
KQL: tags: "sysmon"
```

Filter to just process creation:

```
KQL: tags: "process_create"
```

You should see events with `winlog.event_data.Image`, `winlog.event_data.CommandLine`, `winlog.event_data.ParentImage` fields populated.

### Run a Basic Detection Test

Let's verify the pipeline end-to-end with a known-detectable activity. On your Windows 10 VM, open PowerShell and run:

```powershell
# This mimics a common attacker technique running encoded PowerShell
# This is completely harmless but will generate a very detectable Sysmon event
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Write-Host 'Lab pipeline test - detection working'"))
powershell.exe -EncodedCommand $encoded
```

Now go back to Kibana and search:

```
KQL: tags: "process_create" AND winlog.event_data.CommandLine: "-EncodedCommand"
```

If you see your event, the pipeline is fully working from Sysmon on the endpoint, through Winlogbeat, into Logstash, and into Elasticsearch, queryable in Kibana. That's your complete detection pipeline.

---

## Practical Exercise: Detecting a Suspicious Process Chain

Now that everything is working, here's a practical exercise to confirm your lab can detect real attacker behavior patterns.

On the Windows 10 VM, simulate a classic "living off the land" technique using legitimate Windows binaries to run code:

```powershell
# Simulate a suspicious process chain commonly seen in phishing/macro execution
# This chain: Word -> cmd -> powershell is a classic red flag
# We'll simulate it without actually opening Word by creating the same parent-child relationship pattern

cmd.exe /c "powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -Command whoami; hostname; ipconfig /all"
```

In Kibana, run this EQL query (go to Security → Timelines → EQL Search):

```eql
sequence by host.name
  [process where process.name == "cmd.exe" and process.args : "/c"]
  [process where process.name == "powershell.exe" and process.parent.name == "cmd.exe"
    and process.args : ("-NoProfile", "-NonInteractive", "-WindowStyle", "-Command")]
```

This is a basic process chain correlation exactly how production detection rules work. If your lab is functioning, you'll get a hit.

---

## Common Issues and Fixes

**Winlogbeat can't connect to Logstash:**
- Verify the host machine's firewall allows port 5044 inbound
- On Windows host: `netsh advfirewall firewall add rule name="Logstash Beats" dir=in action=allow protocol=TCP localport=5044`
- On Linux host: `sudo ufw allow 5044/tcp`
- Check Docker port binding: `docker port logstash`

**Elasticsearch won't start / exits immediately:**
- Check the vm.max_map_count setting on your Docker host
- On Linux: `sudo sysctl -w vm.max_map_count=262144`
- On Docker Desktop (Windows/Mac): it's configured automatically, but verify Docker has enough RAM allocated in Docker Desktop settings (minimum 4 GB)

**No events in Kibana:**
- Check Logstash logs: `docker compose logs logstash`
- Check Winlogbeat logs on the Windows VM: `C:\Tools\winlogbeat\logs\`
- Verify the index was created: `GET _cat/indices?v` in Dev Tools

**Sysmon events not appearing:**
- Verify Sysmon service is running: `Get-Service Sysmon64`
- Check the event log directly: `Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5`
- The Winlogbeat config must include `Microsoft-Windows-Sysmon/Operational` in the event_logs section

---

## Taking It Further

Once the basic pipeline is working, here's what to layer on next:

**Threat simulation:** Install Atomic Red Team on your Windows 10 VM. It lets you run individual ATT&CK technique simulations and see exactly what Sysmon and Windows event logs produce. Start with T1059.001 (PowerShell), T1021.002 (SMB/Windows Admin Shares), and T1003.001 (LSASS Memory).

**Detection rule development:** Elastic Security has a prebuilt detection rules repo on GitHub. Import them into your lab and see which ones fire against Atomic Red Team tests.

**Elastic Agent:** Once you're comfortable with the Beats-based setup, try replacing Winlogbeat with Elastic Agent for a more integrated experience. Elastic Agent includes endpoint detection capabilities that Winlogbeat doesn't.

**Network visibility:** Add a pfSense VM as your lab gateway with Suricata running on it. Ship Suricata alerts to Elastic alongside your endpoint logs and practice correlating network and endpoint telemetry that's where the interesting detection logic lives.

**Purple team exercises:** Pull down a retired HTB machine or use FLARE VM as a dedicated malware analysis platform. Run samples in the lab and hunt for them in Elastic.

---

## Closing Thoughts

Building this lab took me a weekend the first time. The second time I built it (after accidentally deleting a snapshot that I really shouldn't have deleted), it took about three hours because I knew the failure points. The third time, I had a script for most of it.

The value isn't just in having the environment it's in the process of building it. When you watch Sysmon Event ID 1 fire for a PowerShell process spawned by cmd.exe, and you see exactly which fields contain the parent process info and command line, and you write the KQL query that finds it, you've built intuition that no certification exam can give you. You understand why the detection works, which means you understand how an attacker would evade it, which means you can make a better detection.

That loop attack, detect, understand, improve is the whole game. This lab gives you somewhere to play it.

---

*All configurations in this guide are tuned for a lab environment. Before adapting anything to production, review your organization's logging standards, test for performance impact, and ensure Sysmon configs are reviewed against your baseline noise levels.*

---

**Resource Links:**
- Sysmon: https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon
- SwiftOnSecurity Sysmon Config: https://github.com/SwiftOnSecurity/sysmon-config
- Olaf Hartong Sysmon Modular: https://github.com/olafhartong/sysmon-modular
- Atomic Red Team: https://github.com/redcanaryco/atomic-red-team
- Elastic Security Detection Rules: https://github.com/elastic/detection-rules
- Windows Event Log Encyclopedia: https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/
