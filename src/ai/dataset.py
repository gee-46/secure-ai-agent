"""Small, synthetic, non-sensitive training dataset for the sensitivity classifier.

IMPORTANT: this dataset is deliberately small (a few dozen examples) and
entirely synthetic. It is sufficient to demonstrate a real, working
ML pipeline for an academic mini-project, but it does NOT provide
production-grade classification accuracy. See docs/PROJECT_REPORT.md
and docs/VIVA_QUESTIONS.md for the discussion of this limitation.
"""
from __future__ import annotations

LABELS = ("Public", "Confidential", "Highly Confidential")

TRAINING_EXAMPLES: list[tuple[str, str]] = [
    # --- Public ---
    ("Our company picnic is scheduled for next Friday in the main park.", "Public"),
    ("The new office opening hours are 9 AM to 6 PM starting Monday.", "Public"),
    ("Please find attached the public press release about our product launch.", "Public"),
    ("The quarterly newsletter highlights our community volunteering events.", "Public"),
    ("This is a general reminder that the cafeteria menu changes weekly.", "Public"),
    ("Our website redesign goes live next month, check out the new homepage.", "Public"),
    ("The conference schedule and public agenda are posted on the notice board.", "Public"),
    ("Welcome to the team! Here is the general employee handbook overview.", "Public"),
    ("The marketing team shared the public blog post about our new feature.", "Public"),
    ("Reminder: the fire drill will take place this Thursday afternoon.", "Public"),
    ("Our annual public sustainability report is now available on the site.", "Public"),
    ("The office holiday schedule for this year has been published.", "Public"),

    # --- Confidential ---
    ("Please review the internal project budget before the Friday meeting.", "Confidential"),
    ("Contact John at john.doe@example.com regarding the vendor contract draft.", "Confidential"),
    ("The internal sales forecast for next quarter is attached for review.", "Confidential"),
    ("Call me at 555-234-9876 to discuss the client proposal details.", "Confidential"),
    ("This document contains internal performance review notes for the team.", "Confidential"),
    ("Please keep this internal roadmap confidential until the launch date.", "Confidential"),
    ("The invoice amount for this vendor contract needs manager approval.", "Confidential"),
    ("Internal memo: upcoming reorganization details for department heads.", "Confidential"),
    ("Please update the internal pricing sheet before sending to partners.", "Confidential"),
    ("The salary adjustment spreadsheet for the team is attached, internal only.", "Confidential"),
    ("Draft partnership terms are confidential until legal sign-off is complete.", "Confidential"),
    ("Internal audit notes regarding the upcoming vendor review are attached.", "Confidential"),

    # --- Highly Confidential ---
    ("Patient diagnosis: Type 2 diabetes. Treatment plan attached, account ACCT-88213.", "Highly Confidential"),
    ("Employee SSN: 523-44-1278 and bank account routing number for payroll setup.", "Highly Confidential"),
    ("Here is the database password and API key for the production environment.", "Highly Confidential"),
    ("Medical record: patient prescription details and health insurance claim number.", "Highly Confidential"),
    ("Credit card number 4111 1111 1111 1111 was used for the reimbursement.", "Highly Confidential"),
    ("This file contains the private key passphrase used for the signing server.", "Highly Confidential"),
    ("Account ID ACC-552391 shows a wire transfer of company funds overseas.", "Highly Confidential"),
    ("Patient treatment plan and HIV test results are enclosed for the specialist.", "Highly Confidential"),
    ("Please secure this file: it contains customer credit score and tax id data.", "Highly Confidential"),
    ("The attached spreadsheet has employee social security numbers for all staff.", "Highly Confidential"),
    ("Secret key and admin password for the core banking system are listed below.", "Highly Confidential"),
    ("Patient medical record ACCT-77102 includes diagnosis and prescription history.", "Highly Confidential"),
]
