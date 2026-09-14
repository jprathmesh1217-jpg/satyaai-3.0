# Banking Fraud & Account Takeover Scams

## Overview
Banking scams involve unauthorized attempts to access consumer or corporate bank accounts, siphon funds, or manipulate victims into authorizing fraudulent wire transfers and electronic debits.

## Common Modus Operandi
1. **Fake Customer Support**: Scammers post fraudulent customer care helpline numbers on Google Maps, social media, and spoofed search engine ads.
2. **Account Suspension Alerts**: SMS or WhatsApp messages claiming "Your Bank Account has been frozen due to suspicious activity. Update details immediately to reactivate."
3. **Unauthorized Debit Reversal Trap**: Victims receive a fake SMS stating a large sum was debited. When they call the helpline number provided in the message, the scammer pretends to "reverse" the charge by asking for card details and OTPs.
4. **Remote Access Trojan (RAT) Installation**: Attackers convince the victim to install remote desktop tools (AnyDesk, TeamViewer QuickSupport, RustDesk) under the guise of technical support to gain total device control.

## Red Flags & Indicators
- Caller asks you to read out an OTP received on your phone.
- Caller instructs you to download an `.apk` file or third-party remote screen-sharing software.
- Demands that money be transferred to an "escrow account" or "safe RBI holding wallet" for verification.
- Messages originating from 10-digit mobile numbers claiming to represent major banks instead of authorized alphanumeric sender IDs (e.g., `AD-HDFCBK`, `VK-SBIINB`).

## Attacker Objectives
- Primary account liquidation via IMPS/NEFT/RTGS transfers.
- Compromising debit/credit card CVV and expiry dates for card-not-present international fraud.
- Secondary identity fraud using stolen account statements.

## Preventive Measures & Incident Response
- Remember: **Banks NEVER ask for OTP, PIN, CVV, or passwords over the phone or SMS.**
- Immediately lock debit/credit cards via the bank's official net-banking or mobile app.
- Call the National Cyber Crime Helpline at **1930** (India) or report at `cybercrime.gov.in`.
