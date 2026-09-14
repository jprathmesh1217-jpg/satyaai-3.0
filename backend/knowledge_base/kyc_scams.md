# KYC (Know Your Customer) Verification Scams

## Overview
KYC scams leverage mandatory regulatory compliance mandates (telecom SIM verification, banking KYC, PAN-Aadhaar linking) to instill panic, prompting victims into clicking malicious links or installing spyware APKs.

## Typical Attack Vectors
1. **Urgent Account/SIM Deactivation Threats**:
   - "Dear SBI User, your account has been blocked due to non-compliance with KYC regulations. Please click http://bit.ly/sbi-kyc-update to upload documents within 24 hours to avoid permanent suspension."
2. **Malicious Android Application (.APK) Distribution**:
   - Victims are told to download a specific "Bank KYC Portal" or "Quick KYC Assistant" APK file directly from WhatsApp, Telegram, or third-party file-hosting domains.
   - The installed APK requests `RECEIVE_SMS`, `READ_SMS`, and accessibility permissions to intercept incoming bank OTPs silently in the background.
3. **Document Harvesting Portals**:
   - Counterfeit portals solicit high-resolution scans of Aadhaar cards, PAN cards, passport photos, and signature samples, facilitating unauthorized loan applications and identity theft.

## Critical Indicators
- SMS or WhatsApp message sent from standard 10-digit consumer phone numbers rather than registered corporate bulk SMS sender IDs.
- High-pressure countdowns ("Action required within 12 hours").
- Direct download links to `.apk` files outside the Google Play Store or Apple App Store.
- Forms requesting debit card ATM PINs or CVVs under the guise of "identity authentication".

## Protective Guidelines
- Banks and telecom service providers **never** process KYC updates via external WhatsApp links or APK downloads.
- Official KYC updates are conducted exclusively through official bank branches, authorized video-KYC within official banking apps, or official telecom retailer stores.
- If an unknown APK was installed, immediately turn on Airplane Mode, disconnect from Wi-Fi, uninstall the application, and format the device.
