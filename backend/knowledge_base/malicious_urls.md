# Malicious URLs, Phishing Domains & Web Redirection

## Overview
Malicious URLs serve as the delivery vehicle for credential harvesting landing pages, drive-by malware downloads, and automated exploit kits. Attackers craft URLs designed to bypass visual inspection and email security filters.

## Structural Anatomy of Suspicious URLs
1. **Raw IP Address Usage**:
   - Legitimate institutions use registered domain names. URLs structured as `http://192.168.1.105/banking-login` or `http://45.33.32.156/verify` are strong red flags.
2. **Deceptive Subdomain Stacking**:
   - Attackers place legitimate brand names in subdomains while the actual root domain belongs to the attacker:
     `https://www.paypal.com.account-verification-service.ru/` (The actual domain is `account-verification-service.ru`, NOT `paypal.com`).
3. **Typosquatting & Homoglyphs**:
   - Swapping visually similar characters or misspellings: `amz0n.com`, `paypa1.com`, or Unicode punycode substitutions (`xn--...`).
4. **URL Shortening & Multiple Redirect Chains**:
   - Utilizing bit.ly, tinyurl, or is.gd to obscure the destination domain and evade static reputation scanners.
5. **Suspicious Keyword Densities**:
   - High occurrences of words like `login`, `verify`, `secure`, `update`, `banking`, `kyc`, `bonus`, or `free` combined with non-standard generic Top-Level Domains (gTLDs like `.top`, `.xyz`, `.club`, `.work`, `.ru`).

## Threat Objectives
- Capture credentials through real-time reverse proxies.
- Trigger silent zero-day browser exploit kits or download malicious payloads (`.apk`, `.exe`, `.scr`).

## Verification Protocols
- **Inspect the Root Domain**: Read the domain immediately preceding the first single forward slash (`/`).
- Use URL expansion tools or passive DNS query services before opening links.
- Check SSL certificate issuer: Legitimate enterprise portals hold Extended Validation or Organization Validation certificates, not automated temporary domain-validated certs.
