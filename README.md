# SOC Automation & Alert Triage Platform

A Security Operations Center (SOC) lab that automates the full path from raw endpoint activity to an analyst-ready incident — detection, threat-intel enrichment, case creation, and notification — with no manual log-digging in between.

Traditional SOC monitoring depends on analysts manually reviewing logs and alerts, which causes delayed response and alert fatigue. This project closes that gap by automatically detecting suspicious activity, enriching it with threat intelligence, creating a structured case, and notifying the analyst — all within seconds of the event occurring.

## What it does

A Windows machine is monitored using **Sysmon** and the **Wazuh Agent**, forwarding detailed endpoint events to a **Wazuh Manager** on Ubuntu. A custom detection rule (**Rule ID 100002**) flags **Mimikatz** activity — a tool commonly used for credential dumping. Once triggered, the alert flows into **Shuffle SOAR**, which extracts key indicators (like SHA256 hashes), checks them against **VirusTotal**, creates a structured case in **TheHive**, and emails the analyst — all without anyone touching a dashboard.

**End-to-end flow:**

```
Windows Endpoint (Sysmon + Wazuh Agent)
        │
        ▼
Wazuh Manager  →  detects Mimikatz via custom Rule ID 100002
        │
        ▼
Shuffle SOAR  →  extracts indicators, triggers automation
        │
        ├──→ VirusTotal  →  threat intelligence enrichment
        │
        ├──→ TheHive (via Ngrok tunnel)  →  structured case creation
        │
        └──→ Email Notification  →  analyst alerted
```

## Tech stack

| Tool | Role |
|---|---|
| **Wazuh** | SIEM — log analysis & rule-based threat detection |
| **Sysmon** | Endpoint-level Windows event logging (process creation, command-line activity) |
| **Shuffle** | SOAR — automation engine tying every tool together |
| **TheHive** | Incident response & case management |
| **VirusTotal** | Threat intelligence enrichment (hash/IOC reputation checks) |
| **Ngrok** | Secure tunnel connecting cloud-based Shuffle to locally hosted TheHive |
| **Docker** | Containerized deployment of TheHive |
| **Mimikatz** | Attack simulation tool (credential dumping) used to test detection |

## Lab architecture

- **Windows 10** — victim endpoint, running Sysmon + Wazuh Agent
- **Ubuntu (VM 1)** — hosts Wazuh Manager & Dashboard
- **Ubuntu (VM 2)** — hosts TheHive via Docker
- **Shuffle Cloud** — automation workflow, connected to local TheHive through an Ngrok tunnel

See `System Architecture.png` and `WorkFlow.png` in the repo root for the full visual breakdown.

## Step-by-step: how it was built

### 1. Set up the lab environment
Created the virtual lab using VMware/VirtualBox — one Windows 10 victim machine, two Ubuntu VMs (one for Wazuh, one for TheHive).

### 2. Installed and configured Sysmon on the Windows endpoint
Sysmon was installed to capture detailed process creation and command-line events that standard Windows logs miss — this is what makes Mimikatz activity actually visible.

### 3. Installed and registered the Wazuh Agent
The agent was installed on the Windows machine and pointed at the Wazuh Manager:

```xml
<client>
  <server>
    <address>10.xx.xx.xxx</address>
    <port>15xx</port>
    <protocol>tcp</protocol>
  </server>
</client>
```

Sysmon's event channel was then added to the agent's log collection config so Wazuh actually receives those events:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

### 4. Wrote a custom detection rule for Mimikatz
Added directly to Wazuh's local rules file (`/var/ossec/etc/rules/local_rules.xml`), mapped to MITRE ATT&CK technique **T1003 (Credential Dumping)**:

```xml
<group name="windows,sysmon,">
  <rule id="100002" level="15">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.originalFileName" type="pcre2">(?i)mimikatz\.exe</field>
    <description>Mimikatz Usage Detected</description>
    <mitre>
      <id>T1003</id>
    </mitre>
  </rule>
</group>
```

### 5. Built the Shuffle SOAR workflow
Connected a chain of nodes: **Wazuh webhook trigger → extract indicators → VirusTotal lookup → TheHive alert creation → email notification.** This is the piece that turns a raw Wazuh alert into a fully enriched, documented, analyst-ready case with zero manual steps.

### 6. Connected cloud Shuffle to local TheHive via Ngrok
Since Shuffle runs in the cloud and TheHive runs locally, a direct connection isn't possible. Ngrok exposes TheHive's local port publicly:

```bash
ngrok http 9000
```

Shuffle then uses that public Ngrok URL as its TheHive API endpoint.

### 7. Configured the TheHive alert payload
Shuffle builds and sends this payload to TheHive's API on every detection:

```json
{
  "description": "Mimikatz Detected on host: $exec.text.win.system.computer",
  "severity": 2,
  "source": "Wazuh",
  "sourceRef": "Rule:100002",
  "title": "Mimikatz Detection Alert",
  "type": "Internal",
  "tags": ["T1003"]
}
```

### 8. Set up email notification
Configured Shuffle's email node to send a formatted alert straight to the analyst's inbox the moment a case is created:

```
MIMIKATZ DETECTED - SOC ALERT

Host: $exec.text.win.system.computer
Rule ID: 100002
Source: Wazuh SIEM
Process: $exec.text.win.eventdata.image
Command Line: $exec.text.win.eventdata.commandLine
Action: Review alert in TheHive and investigate the affected system.
```

### 9. Tested end-to-end with a real attack simulation
Ran Mimikatz on the Windows victim machine to generate genuine credential-dumping activity, then verified every link in the chain:

- ✅ Sysmon captures the event
- ✅ Wazuh Agent forwards it
- ✅ Rule 100002 triggers in Wazuh
- ✅ Shuffle receives and processes the alert
- ✅ VirusTotal enrichment completes
- ✅ TheHive case is created
- ✅ Email notification is delivered

## Screenshots

This repo is organized by tool — each folder below contains the screenshots demonstrating that component working:

- **`wazuh/`** — Dashboard login, agent status, Sysmon log collection, Mimikatz detection alert (Rule 100002 firing)
- **`Sysmon/`** — Endpoint event collection on the Windows victim machine
- **`Mimikatz/`** — Attack simulation in progress
- **`Shuffle/`** — The full automation workflow and node configuration
- **`VirusTotal/`** — Hash/indicator enrichment results
- **`TheHive/`** — Login, alert creation, and full case detail view
- **`Ngrok/`** — Active tunnel connecting cloud Shuffle to local TheHive
- **`Email/`** — The final notification as received by the analyst

## Why Mimikatz / credential dumping

Credential dumping (MITRE ATT&CK **T1003**) is one of the most consequential post-compromise techniques — once an attacker has valid credentials, they can move laterally across a network largely undetected. Catching it fast, automatically, and with enough context to act on immediately is exactly the kind of problem real SOC teams deal with daily. This project builds and tests a working pipeline for exactly that scenario, end to end.

## Future improvements

- Additional detection rules (ransomware behavior, brute-force attempts, privilege escalation)
- Automated response actions — IP blocking, endpoint isolation, account suspension
- Multi-endpoint monitoring across a simulated network, not just one victim machine
- Slack/Teams notifications alongside email
- ML-based alert prioritization to cut down false positives at scale
