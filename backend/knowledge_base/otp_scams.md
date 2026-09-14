# One-Time Password (OTP) & 2FA Bypass Scams

## Overview
One-Time Password (OTP) scams occur when cybercriminals use manipulation, pretexts, or technical interception to obtain authentication tokens needed to finalize unauthorized financial transactions, SIM swaps, or account logins.

## Attack Vectors
1. **Urgent Verification Deception**:
   - The caller claims to be from your bank's fraud detection team: "We noticed an unauthorized transaction of Rs 45,000. To block this transaction immediately, please confirm the 6-digit cancellation OTP sent to your phone."
   - In reality, the OTP received is the authorization code to *debit* the funds or bind a new device.
2. **Screen Sharing Manipulation**:
   - Attackers ask victims to install remote viewing apps to resolve a minor payment glitch. As soon as the victim receives an SMS, the attacker reads the OTP off the victim's mirrored screen.
3. **SMS Forwarding Malicious Codes**:
   - Victims are tricked into dialing MMI codes like `*21*<attacker_number>#` or `*401*<attacker_number>#`, which redirects all incoming calls and SMS messages to the fraudster's handset.
4. **SIM Swap Fraud**:
   - Fraudsters obtain a duplicate SIM card using fabricated IDs or phishing verification codes, cutting off the legitimate owner's cellular connectivity and capturing all subsequent banking OTPs.

## Red Flags
- Any request asking you to share, read aloud, or forward an OTP.
- The SMS clearly states: *"Do NOT share this code with anyone, including bank staff"*, but the caller insists they are exempt.
- Sudden loss of cellular network reception followed by unexpected password reset notifications.

## Best Practices
- **Absolute Rule**: Never disclose an OTP, 2FA code, or password to anyone under any circumstances.
- Carefully read the transaction amount and merchant name stated inside the OTP SMS body before typing it into an official portal.
- If cellular signal suddenly drops and does not return, contact your telecom provider immediately from a secondary phone to check for unauthorized SIM swap requests.
