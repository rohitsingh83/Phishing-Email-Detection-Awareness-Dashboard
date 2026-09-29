"""
Synthetic Email Dataset Generator for Phishing Email Detection & Awareness Dashboard
Generates 550+ diverse, realistic, and completely safe synthetic emails (Legitimate & Phishing).
All URLs and domains use reserved RFC 2606 domains (example.com, example.org, invalid.test)
and RFC 5737 test IP addresses (198.51.100.x, 203.0.113.x).
"""

import csv
import os
import random

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
OUTPUT_FILE = os.path.join(DATA_DIR, "phishing_email_dataset.csv")

# Ensure data directory exists
os.makedirs(DATA_DIR, exist_ok=True)

# Seed for reproducibility
random.seed(42)

# Templates for Legitimate Emails (Categories: HR, University, IT/Support, Shopping, Banking/Notification, Meeting)
LEGITIMATE_TEMPLATES = [
    {
        "sender": "{name}@{company}.example.com",
        "sender_domain": "{company}.example.com",
        "subject": "Quarterly All-Hands Meeting Schedule - {quarter}",
        "body": "Hi Team,\n\nPlease find the schedule for our upcoming quarterly all-hands meeting on Friday at 2:00 PM EST.\nWe will review department accomplishments and Q3 goals.\n\nAgenda:\n1. Executive Summary\n2. Department Updates\n3. Q&A Session\n\nYou can review the slide deck on our internal knowledge base: https://portal.{company}.example.com/meetings/all-hands\n\nBest regards,\n{name}\nInternal Communications Team",
        "urls": "https://portal.{company}.example.com/meetings/all-hands",
        "attachment": "All_Hands_Agenda.pdf"
    },
    {
        "sender": "hr-benefits@{company}.example.org",
        "sender_domain": "{company}.example.org",
        "subject": "Annual Health Benefits Open Enrollment Window",
        "body": "Dear Employee,\n\nThe annual benefits enrollment period will open next Monday and run through November 15.\nDuring this window, you can review or modify your medical, dental, and vision insurance coverage.\n\nDetailed benefit summaries and contribution calculators are available on the employee intranet:\nhttps://intranet.{company}.example.org/hr/benefits-2026\n\nPlease reach out to hr-benefits@{company}.example.org if you have any questions.\n\nSincerely,\nHuman Resources Department",
        "urls": "https://intranet.{company}.example.org/hr/benefits-2026",
        "attachment": "Benefits_Guide_2026.pdf"
    },
    {
        "sender": "it-service-desk@{company}.example.com",
        "sender_domain": "{company}.example.com",
        "subject": "Scheduled Maintenance Notice: Campus Network Upgrades",
        "body": "Hello Everyone,\n\nIT Services will perform routine network infrastructure upgrades this Saturday between 1:00 AM and 5:00 AM.\nDuring this maintenance window, access to Wi-Fi and internal file shares may experience brief intermittent interruptions.\n\nNo action is required on your part. Cloud applications such as email and video conferencing will remain accessible.\n\nTrack status updates on our service portal: https://status.{company}.example.com\n\nThank you for your patience,\nIT Infrastructure Operations",
        "urls": "https://status.{company}.example.com",
        "attachment": ""
    },
    {
        "sender": "registrar@{university}.example.edu",
        "sender_domain": "{university}.example.edu",
        "subject": "Fall Semester Final Exam Schedule and Academic Guidelines",
        "body": "Dear Students,\n\nThe official final exam schedule for the Fall semester is now published.\nPlease review your specific exam times and classroom allocations through the student registration portal:\nhttps://studentportal.{university}.example.edu/exams\n\nRemember to bring your university student ID card to all exam venues.\n\nBest wishes on your upcoming evaluations,\nOffice of the University Registrar",
        "urls": "https://studentportal.{university}.example.edu/exams",
        "attachment": "Exam_Regulations.pdf"
    },
    {
        "sender": "library-services@{university}.example.edu",
        "sender_domain": "{university}.example.edu",
        "subject": "Book Return Reminder: Due in 3 Days",
        "body": "Hello {student},\n\nThis is a courtesy reminder that the following borrowed library book is due on Thursday:\nTitle: Foundations of Computer Networks and Distributed Systems\n\nYou can renew this item online if no hold requests have been placed by other students:\nhttps://library.{university}.example.edu/renewals\n\nThank you for utilizing campus library resources,\nUniversity Library Circulations",
        "urls": "https://library.{university}.example.edu/renewals",
        "attachment": ""
    },
    {
        "sender": "orders@store.example.com",
        "sender_domain": "store.example.com",
        "subject": "Order Confirmation #{order_id} - Thank you for shopping with us",
        "body": "Hi {customer},\n\nWe have received your order #{order_id} placed on {date}.\nYour items are currently being prepared for shipment. You will receive another notification with tracking details as soon as the package leaves our warehouse.\n\nView order details: https://store.example.com/account/orders/{order_id}\n\nEstimated delivery: 3-5 business days.\n\nThank you,\nCustomer Care Team",
        "urls": "https://store.example.com/account/orders/{order_id}",
        "attachment": "Receipt_{order_id}.pdf"
    },
    {
        "sender": "notifications@bank-notify.example.org",
        "sender_domain": "bank-notify.example.org",
        "subject": "Your Monthly Account Statement is Ready (Account ending in {acc})",
        "body": "Dear Valued Customer,\n\nYour latest monthly e-statement for account ending in {acc} is now ready for viewing.\nTo protect your financial security, we do not attach financial statements directly to email notifications.\n\nPlease log in to your official online banking profile via your standard mobile app or browser bookmark:\nhttps://online.bank-notify.example.org/statements\n\nAs a reminder, our bank will never ask you for your PIN, one-time passcode, or password via email or SMS.\n\nSincerely,\nCustomer Account Services",
        "urls": "https://online.bank-notify.example.org/statements",
        "attachment": ""
    },
    {
        "sender": "pm-office@{company}.example.net",
        "sender_domain": "{company}.example.net",
        "subject": "Project Sprint Review & Retrospective Notes",
        "body": "Hi team,\n\nThanks everyone for the productive sprint review meeting earlier today.\nThe action items and sprint retrospective notes have been documented on our project board:\nhttps://projects.{company}.example.net/board/sprint-42\n\nKey takeaways:\n- Velocity increased by 14%\n- Backend API refactoring completed on time\n- Next sprint planning kicks off on Monday at 10 AM\n\nHave a great weekend,\n{name}\nTechnical Project Manager",
        "urls": "https://projects.{company}.example.net/board/sprint-42",
        "attachment": "Sprint_Metrics.xlsx"
    },
    {
        "sender": "newsletter@techinsights.example.org",
        "sender_domain": "techinsights.example.org",
        "subject": "Weekly Tech Digest: Cloud Trends, Cybersecurity Insights & AI",
        "body": "Hello Reader,\n\nWelcome to this week's edition of Tech Insights Digest.\nIn this issue:\n- How zero-trust architectures protect modern workforces\n- Machine learning optimizations in production pipelines\n- Open source security tooling highlights for 2026\n\nRead the full issue: https://techinsights.example.org/weekly/issue-184\n\nYou are receiving this email because you subscribed to Tech Insights. Manage preferences: https://techinsights.example.org/preferences\n\nTech Insights Editorial Staff",
        "urls": "https://techinsights.example.org/weekly/issue-184",
        "attachment": ""
    },
    {
        "sender": "security-team@{company}.example.com",
        "sender_domain": "{company}.example.com",
        "subject": "Password Change Completed Successfully",
        "body": "Dear Employee,\n\nThis notification confirms that the password for your corporate domain user account was changed on {date}.\n\nIf you performed this action, no further steps are required.\nIf you did NOT authorize this change, please contact the IT Security Operations Helpdesk immediately at extension 4357 or via our internal security ticketing system:\nhttps://servicedesk.{company}.example.com/tickets\n\nRegards,\nCorporate Information Security Operations",
        "urls": "https://servicedesk.{company}.example.com/tickets",
        "attachment": ""
    }
]

# Templates for Phishing Emails (Categories: Credential Harvest, Urgent Suspension, Fake Invoice, Fake Prize, Delivery Failure, Fake HR/Executive Impersonation)
PHISHING_TEMPLATES = [
    {
        "sender": "security-alert@account-verify.invalid.test",
        "sender_domain": "account-verify.invalid.test",
        "subject": "URGENT: Immediate Account Verification Required Within 24 Hours",
        "body": "Dear Valued Customer / Account Holder,\n\nWe detected suspicious and unauthorized login attempts to your account from an unknown IP address.\nTo protect your funds and personal information, your account access has been temporarily restricted.\n\nACT NOW: You must verify your credentials immediately to avoid permanent account termination.\nFailure to confirm your password and identity within 24 hours will result in permanent suspension.\n\nClick below to verify your account right now:\nhttp://198.51.100.10/verify-account-login\n\nDo not ignore this warning.\n\nSecurity Department",
        "urls": "http://198.51.100.10/verify-account-login",
        "attachment": ""
    },
    {
        "sender": "billing-support@invoicing-desk.invalid.test",
        "sender_domain": "invoicing-desk.invalid.test",
        "subject": "OVERDUE INVOICE #{order_id}: Immediate Payment Required to Avoid Legal Action",
        "body": "Attn: Accounts Payable / Account Owner,\n\nOur records indicate an outstanding balance of $3,840.00 on Invoice #{order_id} which is now severely past due.\nUnless immediate payment is processed today, your account will be turned over to our third-party debt collection agency and legal action will commence.\n\nPlease review the attached invoice statement and remittance voucher immediately:\nDownload invoice: http://invoicing-desk.invalid.test/pay-now-portal?ref={order_id}\n\nPlease find the attached breakdown invoice document.\n\nAccounting Department",
        "urls": "http://invoicing-desk.invalid.test/pay-now-portal?ref={order_id}",
        "attachment": "Invoice_Overdue_{order_id}.pdf.exe"
    },
    {
        "sender": "winner-notification@international-lottery.invalid.test",
        "sender_domain": "international-lottery.invalid.test",
        "subject": "CONGRATULATIONS! You Have Won $2,500,000 Cash Prize in Annual Lottery Draw",
        "body": "Dear Lucky Winner,\n\nWe are pleased to inform you that your email address was selected as the 1st prize winner in our International Mega Promotion Draw 2026!\nYou have been awarded a lump sum payout of $2,500,000.00 USD.\n\nTo claim your winnings, you must confirm your personal details immediately:\n1. Full Legal Name\n2. Date of Birth\n3. Home Address & Phone Number\n4. Bank Account Routing Number\n\nClick here to submit your claim form and verify identity: http://203.0.113.45/claims/winner-verification\n\nAct now! Unclaimed prizes will be forfeited after 48 hours.\n\nClaims Department",
        "urls": "http://203.0.113.45/claims/winner-verification",
        "attachment": "ClaimForm.vbs"
    },
    {
        "sender": "it-desk@global-system-update.invalid.test",
        "sender_domain": "global-system-update.invalid.test",
        "subject": "CRITICAL: Password Expiration Notice - Upgrade Email Quota Immediately",
        "body": "Attention Employee,\n\nYour corporate email password and mailbox storage quota will expire in 2 hours.\nAll incoming and outgoing communications will be blocked unless you confirm your existing password and upgrade your mailbox capacity.\n\nKeep Same Password and Retain Access: Click Here Immediately:\nhttp://login.corporate-mail.invalid.test/user-portal/login.php\n\nEnter your email, current password, and two-factor code to restore full access.\n\nIT Support Helpdesk",
        "urls": "http://login.corporate-mail.invalid.test/user-portal/login.php",
        "attachment": "Update_Patch.bat"
    },
    {
        "sender": "tracking-update@express-courier.invalid.test",
        "sender_domain": "express-courier.invalid.test",
        "subject": "Delivery Exception: Your Package Could Not Be Delivered Today",
        "body": "Dear Customer,\n\nOur courier was unable to deliver your package #{order_id} due to an incomplete delivery address on file.\nA fee of $2.95 is required for redelivery.\n\nPlease update your shipping address and confirm your payment card details within 12 hours or your parcel will be returned to sender:\nhttp://track-parcel-express.invalid.test/update-address?pkg={order_id}\n\nTrack parcel and reschedule delivery now.\n\nExpress Courier Service",
        "urls": "http://track-parcel-express.invalid.test/update-address?pkg={order_id}",
        "attachment": "DeliveryReceipt_{order_id}.scr"
    },
    {
        "sender": "ceo-direct@executive-urgent-board.invalid.test",
        "sender_domain": "executive-urgent-board.invalid.test",
        "subject": "QUICK REQUEST: Need urgent purchase done immediately",
        "body": "Are you at your desk right now?\n\nI am currently tied up in an emergency executive board meeting and cannot take phone calls.\nI need you to urgently process an emergency purchase of 5x $200 Apple / Google Play gift cards for a critical client presentation.\n\nPlease purchase them immediately, scratch off the back, and reply with the codes and receipt.\nI will ensure finance reimburses you by end of day.\n\nTreat this with utmost confidentiality and speed.\n\nSent from my iPhone",
        "urls": "",
        "attachment": ""
    },
    {
        "sender": "payroll-update@company-benefits-review.invalid.test",
        "sender_domain": "company-benefits-review.invalid.test",
        "subject": "MANDATORY: Verify Direct Deposit and Tax Information Immediately",
        "body": "Dear Colleague,\n\nDue to updated tax compliance regulations, all employees are required to verify their direct deposit bank accounts and Social Security numbers by 5:00 PM today.\nFailure to verify your details will result in your upcoming payroll check being delayed indefinitely.\n\nReview and submit your payroll verification form here:\nhttp://payroll-portal.auth-portal.invalid.test/direct-deposit\n\nCorporate Payroll & Human Resources",
        "urls": "http://payroll-portal.auth-portal.invalid.test/direct-deposit",
        "attachment": "DirectDepositForm.pdf.js"
    },
    {
        "sender": "cloud-security@storage-quota-warning.invalid.test",
        "sender_domain": "storage-quota-warning.invalid.test",
        "subject": "Storage Alert: 99.8% Quota Exceeded - Delete files or re-authenticate",
        "body": "Alert:\n\nYour cloud mailbox and file storage has reached 99.8% of allocated capacity.\nImportant incoming client messages are currently bouncing.\n\nClick the link below immediately to expand your quota to 50 GB free of charge:\nhttp://198.51.100.88/cloud-storage/quota-expand\n\nEnter your credentials to validate account entitlement.\n\nCloud Operations Center",
        "urls": "http://198.51.100.88/cloud-storage/quota-expand",
        "attachment": ""
    }
]

COMPANIES = ["acmecorp", "novasolutions", "apextech", "brightline", "vanguard", "crestview", "synapse"]
UNIVERSITIES = ["stanford-sample", "mit-sample", "oxford-sample", "berkeley-sample", "cambridge-sample"]
NAMES = ["Alex Morgan", "Jordan Lee", "Taylor Swift", "David Miller", "Sarah Jenkins", "Michael Chang", "Emily Davis"]
CUSTOMERS = ["Valued Member", "Customer", "Client", "Account Holder", "Subscriber"]
DATES = ["October 12, 2026", "November 04, 2026", "September 28, 2026", "August 15, 2026", "December 01, 2026"]
QUARTERS = ["Q1 2026", "Q2 2026", "Q3 2026", "Q4 2026"]


def generate_dataset(total_records=600):
    records = []
    half = total_records // 2

    # 1. Generate Legitimate records
    for i in range(1, half + 1):
        tmpl = random.choice(LEGITIMATE_TEMPLATES)
        company = random.choice(COMPANIES)
        university = random.choice(UNIVERSITIES)
        name = random.choice(NAMES)
        customer = random.choice(CUSTOMERS)
        order_id = random.randint(100450, 998200)
        acc = random.randint(1000, 9999)
        date = random.choice(DATES)
        quarter = random.choice(QUARTERS)

        fmt_kwargs = {
            "company": company,
            "university": university,
            "name": name,
            "customer": customer,
            "student": name,
            "order_id": order_id,
            "acc": acc,
            "date": date,
            "quarter": quarter
        }

        sender = tmpl["sender"].format(**fmt_kwargs)
        sender_domain = tmpl["sender_domain"].format(**fmt_kwargs)
        subject = tmpl["subject"].format(**fmt_kwargs)
        body = tmpl["body"].format(**fmt_kwargs)
        urls = tmpl["urls"].format(**fmt_kwargs) if tmpl["urls"] else ""
        attachment = tmpl["attachment"].format(**fmt_kwargs) if tmpl["attachment"] else ""

        records.append({
            "email_id": f"LEGIT_{i:04d}",
            "sender": sender,
            "sender_domain": sender_domain,
            "subject": subject,
            "body": body,
            "urls": urls,
            "attachment_name": attachment,
            "label": "LEGITIMATE"
        })

    # 2. Generate Phishing records
    for i in range(1, half + 1):
        tmpl = random.choice(PHISHING_TEMPLATES)
        name = random.choice(NAMES)
        order_id = random.randint(100450, 998200)
        date = random.choice(DATES)

        fmt_kwargs = {
            "name": name,
            "order_id": order_id,
            "date": date
        }

        sender = tmpl["sender"].format(**fmt_kwargs)
        sender_domain = tmpl["sender_domain"].format(**fmt_kwargs)
        subject = tmpl["subject"].format(**fmt_kwargs)
        body = tmpl["body"].format(**fmt_kwargs)
        urls = tmpl["urls"].format(**fmt_kwargs) if tmpl["urls"] else ""
        attachment = tmpl["attachment"].format(**fmt_kwargs) if tmpl["attachment"] else ""

        records.append({
            "email_id": f"PHISH_{i:04d}",
            "sender": sender,
            "sender_domain": sender_domain,
            "subject": subject,
            "body": body,
            "urls": urls,
            "attachment_name": attachment,
            "label": "PHISHING"
        })

    # Shuffle to interleave legitimate and phishing
    random.shuffle(records)

    # Write to CSV
    fieldnames = ["email_id", "sender", "sender_domain", "subject", "body", "urls", "attachment_name", "label"]
    with open(OUTPUT_FILE, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(records)

    print(f"Generated {len(records)} safe synthetic email records in {OUTPUT_FILE}")
    print(f"Legitimate: {half}, Phishing: {half}")
    return OUTPUT_FILE


if __name__ == "__main__":
    generate_dataset()
