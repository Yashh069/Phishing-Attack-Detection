# Phishing Attack Detection & Incident Investigation (SOC Lab)

##  Overview
This project demonstrates an end-to-end **phishing attack simulation and SOC investigation** performed in a controlled lab environment using **Splunk SIEM**.

A phishing email was delivered to a user, leading to **encoded PowerShell execution** on a Windows endpoint. The activity was **detected, investigated, and analyzed** using SPL queries, replicating a **real-world SOC L1 workflow**.

---

##  Objectives
- Simulate a real phishing attack scenario
- Detect malicious PowerShell execution
- Perform SOC-style alert triage and investigation
- Correlate endpoint telemetry using Splunk
- Document findings as a professional incident report

---

##  Tools & Technologies
- **GoPhish** – Phishing campaign simulation  
- **MailHog** – SMTP mail capture  
- **Windows 10** – Victim endpoint  
- **PowerShell Script Block Logging** (Event ID 4104)  
- **Windows Security Logs** (Event ID 4688)  
- **Splunk Enterprise SIEM**

---

##  Attack Scenario
1. Phishing email sent using GoPhish
2. Email delivered via MailHog SMTP server
3. User clicks the phishing link
4. PowerShell executes an encoded command
5. Endpoint generates security and PowerShell logs
6. Logs ingested into Splunk SIEM
7. SOC investigation initiated

---

##  Detection & Investigation

###  Indicators Observed
- PowerShell executed with **EncodedCommand**
- Use of **ExecutionPolicy Bypass**
- Script execution using **IEX**
- Multiple suspicious PowerShell executions

---

##  SPL Queries Used

### Detect Encoded PowerShell Execution
```spl
index=powershell EventCode=4104
| search ScriptBlockText="*EncodedCommand*"
### Detect PowerShell Process Creation

```spl
index=wineventlog EventCode=4688
| search NewProcessName="*powershell.exe*"
```

**Purpose:**  
Identifies PowerShell process execution on the endpoint after the phishing link was clicked.

---

### Identify Execution Policy Bypass

```spl
index=powershell EventCode=4104
| search ScriptBlockText="*ExecutionPolicy Bypass*"
```

**Purpose:**  
Detects attempts to bypass PowerShell execution restrictions, a common attacker technique.

---

### Detect IEX (Invoke-Expression) Usage

```spl
index=powershell EventCode=4104
| search ScriptBlockText="*IEX*"
```

**Purpose:**  
Flags dynamic execution of malicious scripts often used in fileless attacks.

---

##  Payload Analysis

During the investigation, Base64-encoded PowerShell commands were extracted from Script Block Logging to validate malicious intent.

### Steps Performed
- Identified Base64-encoded payload from Event ID 4104
- Extracted the `EncodedCommand` value from Splunk logs
- Decoded the payload using PowerShell on the endpoint
- Reviewed decoded output for malicious behavior

### Decoding Command Used

```powershell
$enc="<Base64_String>"
[System.Text.Encoding]::Unicode.GetString(
    [System.Convert]::FromBase64String($enc)
)
```

---

##  Analysis Outcome

- Obfuscated PowerShell execution confirmed
- Behavior consistent with phishing-based initial access
- No legitimate administrative activity identified

---

##  MITRE ATT&CK Mapping

| Technique ID | Technique Name |
|-------------|----------------|
| T1566 | Phishing |
| T1059.001 | PowerShell |

---

##  Incident Summary (SOC View)

- **Initial Vector:** Phishing Email  
- **Execution Method:** Encoded PowerShell Command  
- **Detection Source:** Splunk SIEM  
- **Severity:** Medium  
- **SOC Action:** Alert triage, log correlation, payload decoding, incident documentation

---

## 📌 Conclusion

This Proof of Concept demonstrates a realistic SOC L1 workflow — from phishing delivery to endpoint execution, detection, investigation, and reporting — using Splunk SIEM in a controlled lab environment.
