# Phishing Scams & Credential Harvesting

## Overview
Phishing is a deceptive technique where threat actors impersonate legitimate organizations (banks, government agencies, popular web platforms) to lure individuals into revealing sensitive credentials, financial data, or personal identifiable information (PII).

## Core Mechanisms
1. **Domain Spoofing & Lookalikes**: Attackers register typosquatted domains (e.g., `sbi-kyc-verify.com` instead of `onlinesbi.sbi` or `paypal-security-update.ru`).
2. **Artificial Urgency & Fear**: Messages threaten immediate account closure, legal prosecution, or irreversible financial penalties within strict timeframes (e.g., "within 24 hours" or "immediately").
3. **Deceptive Pretexts**: Common pretexts include unauthorized transaction alerts, unclaimed tax refunds, mandatory security patches, or password expiration notices.
4. **Credential Harvesting Landing Pages**: Victims are directed to counterfeit login portals that mirror genuine corporate portals to capture usernames, passwords, and 2FA tokens in real time.

## Key Indicators & Red Flags
- Generic greetings ("Dear Customer") or mismatched email headers/SMS sender headers.
- Embedded links using URL shorteners (bit.ly, tinyurl) or raw numeric IP addresses.
- Requests to verify passwords, PINs, or security questions via an external link.
- Grammatical irregularities, awkward phrasing, or non-standard character substitutions.

## Threat Objectives
- Steal banking credentials, credit card details, or corporate Single Sign-On (SSO) logins.
- Bypass Two-Factor Authentication (2FA) via real-time reverse proxy techniques (e.g., Evilginx).
- Establish initial access for corporate network intrusion and ransomware deployment.

## Actionable Recommendations
- **Do Not Click**: Never click links contained within unprompted SMS or email communications.
- **Direct Navigation**: Manually enter the official website address or use official banking mobile apps.
- **Report & Block**: Report suspicious communications to the official institutional fraud desk and mark as phishing.
