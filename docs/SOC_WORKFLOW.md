# SOC Analyst Triage & Incident Response Playbook

## 1. Role of Automated Detection in the SOC
In an enterprise Security Operations Center (SOC), email remains the primary initial access vector for adversaries targeting corporate networks. SOC Tier 1 and Tier 2 analysts face hundreds of reported suspicious emails daily, leading to **alert fatigue** and triage delays.

**PhishShield** serves as a Tier 1 automated forensic triage tool. It does **NOT** replace analyst judgment; rather, it augments the investigator with immediate risk scoring, contextual indicator highlights, and pre-extracted IOCs.

---

## 2. Standard Operating Procedure (SOP): Phishing Triage Workflow

```
[ Suspicious Email Reported by End-User ]
                   │
                   ▼
     [ Step 1: Initial Ingestion & Triage ]
  - Ingest raw .eml or text headers into PhishShield Console
  - Verify message integrity and envelope metadata
                   │
                   ▼
     [ Step 2: Automated Indicator Review ]
  - Inspect Sender Forensics (Lookalikes, Subdomains, TLDs)
  - Inspect URL Static String Analysis (Raw IPs, Deceptive Schemes)
  - Inspect Attachment Metadata (Double extensions, Scripts)
  - Inspect Content Triggers (Urgency, Credential lures, Threats)
                   │
                   ▼
     [ Step 3: Human Analyst Verification ]
  - Compare Automated Hybrid Threat Score with business context
  - Correlate sender domain with organization's authorized partner list
  - Check internal mail server logs for widespread campaign receipt
                   │
                   ▼
     [ Step 4: Decision & Classification ]
  ┌────────────────────────┬────────────────────────┐
  ▼                        ▼                        ▼
[ Low Risk / False Alarm ] [ Suspicious Lure ]      [ High Risk / Active Phish ]
  - Reassure reporting user - Quarantine message     - Trigger Incident Response (P1/P2)
  - Close ticket as benign  - Submit domain for block- Purge from all user inboxes
                            - Educate reporter       - Reset affected user credentials
                                                     - Revoke active session tokens
                                                     - Block sender domain & IP on SEG/Firewall
```

---

## 3. Incident Containment Actions by Classification

### Case A: HIGH RISK / LIKELY PHISHING (Score 71–100)
1. **Immediate Quarantine:** Block and purge the email hash from all mailboxes across the tenant.
2. **Identity Protection:** If recipient interacted or submitted credentials:
   - Immediately force password reset.
   - Revoke all active OAuth session tokens and refresh tokens.
   - Audit MFA device registrations for unauthorized authenticator additions.
3. **Network Defense:** Add offending IP addresses, sender domains, and target URLs to Secure Email Gateway (SEG) and perimeter proxy blocklists.
4. **Threat Intelligence Feed:** Log extracted IOCs into MISP/OpenCTI for cross-fleet correlation.

### Case B: SUSPICIOUS (Score 41–70)
1. **Analyst Deep Dive:** Inspect whether the email originated from an authorized SaaS provider utilizing third-party mail distribution (e.g. SendGrid, Mailchimp).
2. **Out-of-Band Verification:** Contact internal parties directly via telephone or corporate chat to verify if the communication was legitimately scheduled.
3. **Safe Release or Quarantine:** Release to user if confirmed benign; otherwise escalate to threat containment.

### Case C: SAFE / LOW RISK (Score 0–20)
1. **Benign Resolution:** Validate that no obfuscated links or zero-font techniques bypassed static analysis.
2. **Feedback Loop:** Tag sample in dataset for model recalibration and close case with positive reinforcement to the user.
