# MITRE ATT&CK® Enterprise Framework Alignment

Mapping threat indicators to the globally recognized **MITRE ATT&CK® Framework** allows security engineers and SOC analysts to normalize detections, communicate risk consistently with executive leadership, and integrate detections into Security Information and Event Management (SIEM) correlation rules.

| ATT&CK ID | Tactic | Technique Name | PhishShield Detection Logic & Forensic Rule |
| :--- | :--- | :--- | :--- |
| **T1566.001** | Initial Access | **Spearphishing Attachment** | Flags executable scripts (`.exe, .vbs, .scr, .bat`) and macro-enabled documents delivered via email attachments. |
| **T1566.002** | Initial Access | **Spearphishing Link** | Statically analyzes hyperlinks for deceptive schemes, raw IPv4/IPv6 hostnames, high-abuse TLDs, and URL shortening services. |
| **T1566.003** | Initial Access | **Spearphishing via Service** | Identifies lures mimicking enterprise cloud services (e.g. Office 365, Google Workspace, payroll portals). |
| **T1204.001** | Execution | **User Execution: Malicious Link** | Evaluates social engineering urgency triggers that manipulate users into executing clicks on dangerous external web destinations. |
| **T1204.002** | Execution | **User Execution: Malicious File** | Flags weaponized file formats designed to execute payload code upon opening. |
| **T1036.007** | Defense Evasion | **Double File Extension** | Forensic detection of masqueraded filenames containing multiple period-delimited extensions (e.g., `Statement.pdf.exe`). |
| **T1036.005** | Defense Evasion | **Match Legitimate Name or Location** | Flags display-name spoofing and brand lookalike/typosquatting permutations (e.g., `micr0soft`, `paypa1`). |
| **T1078** | Credential Access | **Valid Accounts (Credential Access)** | Detects requests targeting authentication credentials, one-time passcodes (OTP/2FA), and sensitive personally identifiable information (PII). |

---

## Strategic Value of MITRE ATT&CK Mapping
1. **Defensive Gap Analysis:** Highlights which phases of the adversary lifecycle are covered by static pre-delivery inspection versus post-delivery endpoint controls.
2. **Standardized Alerting:** Enables SIEM rules to tag alerts with standardized technique identifiers for automated playbook dispatch in SOAR platforms.
3. **Cross-Team Communication:** Bridges the gap between threat intelligence analysts (who track threat actors), SOC triage analysts, and executive CISOs.
