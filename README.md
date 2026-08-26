# 🛡️ Enterprise SIEM Detection & Threat Monitoring Lab

## 📌 Project Overview
This project documents an end-to-end Enterprise SOC lab environment designed to simulate real-world attack scenarios, ingest telemetry from Windows endpoints via **Sysmon** and **Windows Event Logs**, and author custom detection rules in **Splunk (SPL)** aligned with the **MITRE ATT&CK framework**.

---

## 🏗️ Lab Architecture & Setup
- **SIEM Platform:** Splunk Enterprise (Central Log Collector & Search Head)
- **Target Endpoint:** Windows Server / Windows 10 (Domain joined)
- **Telemetry Agents:** Splunk Universal Forwarder + Microsoft Sysmon (SwiftOnSecurity configuration)
- **Attacker Machine:** Kali Linux (Adversary simulation via Metasploit, Hydra, and manual CLI execution)

---

## 🎯 Simulated Attack Scenarios & Detection Rules (SPL)

### 1. Privilege Escalation / Persistence: Local Admin Account Creation
- **MITRE ATT&CK:** [T1136.001 - Create Account: Local Account](https://attack.mitre.org/techniques/T1136/001/)
- **Observed Event:** Execution of `net user /add` or `net localgroup administrators /add`.
- **Telemetry Source:** Windows Security Event Log (`EventID 4720` - User Created / `4728` - Member Added to Security Group).
- **Splunk Detection Query (SPL):**
  \`\`\`spl
  index=windows (EventCode=4720 OR EventCode=4728)
  | stats count by _time, EventCode, TargetUserName, SubjectUserName, ComputerName
  | rename TargetUserName as "Created_User", SubjectUserName as "Created_By"
  \`\`\`

---

### 2. Defense Evasion / Execution: Obfuscated PowerShell Execution
- **MITRE ATT&CK:** [T1059.001 - Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- **Observed Event:** Launching encoded PowerShell payloads (`powershell.exe -enc` / `-nop -w hidden`).
- **Telemetry Source:** Sysmon (`EventID 1` - Process Creation).
- **Splunk Detection Query (SPL):**
  \`\`\`spl
  index=windows EventCode=1 (Image="*\\powershell.exe" OR Image="*\\pwsh.exe") (CommandLine="*-enc*" OR CommandLine="*-encodedcommand*" OR CommandLine="*-w hidden*")
  | table _time, host, User, ParentImage, Image, CommandLine
  \`\`\`

---

### 3. Credential Access: RDP Brute-Force Attack
- **MITRE ATT&CK:** [T1110.001 - Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/)
- **Observed Event:** Repeated logon failures followed by a successful logon over port 3389.
- **Telemetry Source:** Windows Security Log (`EventID 4625` - Failed Logon, `EventID 4624` - Successful Logon with LogonType 10).
- **Splunk Detection Query (SPL):**
  \`\`\`spl
  index=windows EventCode=4625 Logon_Type=10
  | stats count by src_ip, TargetUserName
  | where count > 10
  | sort - count
  \`\`\`

---

## 📊 Incident Triage & Investigation Workflow
1. **Detection & Triage:** Alert triggered via Splunk Correlation Search.
2. **Context Gathering:** Inspecting parent/child process relationships via Sysmon Event ID 1.
3. **True Positive Validation:** Cross-referencing timestamps, user privileges, and source network connections.
4. **Containment & Remediation:**
   - Terminate rogue processes via EDR / PowerShell.
   - Disable compromised accounts and enforce credential rotation.
   - Block malicious source IPs at firewall/perimeter level.

---

## 👤 Author
- **Nehoray Gigi** — [LinkedIn Profile](https://www.linkedin.com/in/nehoray-gigi-1a2053403) | [GitHub](https://github.com/nehoraygigi12)
