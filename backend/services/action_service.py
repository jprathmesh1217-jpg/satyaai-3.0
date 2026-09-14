"""
SATYA AI 3.0 — Recommended Action Engine
Generates prioritized immediate actions, safety avoid rules, and verification guidance
tailored to risk level, input modality, detected evidence, and specific scam categories.
"""

from typing import Any, Dict, List, Set


# ─── Category Specific Knowledge Base ───────────────────────────────────────

CATEGORY_RULES: Dict[str, Dict[str, List[str]]] = {
    "upi": {
        "actions": [
            "Verify the recipient name and payment request details before approving any transaction",
            "Report unauthorized payment requests directly inside your UPI app",
        ],
        "avoid": [
            "Do not approve unknown collect requests",
            "Never enter your UPI PIN to receive money (entering a PIN always debits your account)",
        ],
        "verification": [
            "Verify the recipient name and payment request before approving.",
        ],
    },
    "otp": {
        "actions": [
            "Check SMS headers to verify legitimate sender codes",
            "If an OTP was shared inadvertently, freeze your bank account or block card immediately",
        ],
        "avoid": [
            "Never share OTP with anyone under any circumstances",
            "Never share banking authentication codes or 2FA prompts over call or message",
        ],
        "verification": [
            "Legitimate organizations will never call or text asking you to read out an OTP.",
        ],
    },
    "kyc": {
        "actions": [
            "Verify your account status exclusively through your bank or service provider's official mobile app",
        ],
        "avoid": [
            "Do not send identity documents (Aadhaar, PAN, passport) to unknown contacts or unofficial numbers",
            "Do not upload documents to unverified third-party web forms",
        ],
        "verification": [
            "Contact the organization using contact details obtained independently.",
            "Complete KYC verification only in-person at an official branch or inside the bank's official application.",
        ],
    },
    "banking": {
        "actions": [
            "Contact your bank using the customer service number printed on the back of your debit/credit card",
            "Log into your banking account only through the official verified application or bookmarked portal",
        ],
        "avoid": [
            "Do not call phone numbers provided inside suspicious SMS or email alerts",
            "Do not click links claiming your bank account or debit card has been blocked",
        ],
        "verification": [
            "Open your bank's official app manually instead of using the provided link.",
        ],
    },
    "investment": {
        "actions": [
            "Check if the investment firm or brokerage is officially registered with securities regulators",
            "Consult a certified financial advisor before committing funds to high-yield schemes",
        ],
        "avoid": [
            "Do not transfer additional money or pay 'withdrawal fees' to unlock earnings",
            "Be suspicious of guaranteed high returns or risk-free trading promises",
        ],
        "verification": [
            "Verify the investment platform through independent sources.",
        ],
    },
    "job": {
        "actions": [
            "Verify job postings on the employer's official career website or corporate LinkedIn page",
        ],
        "avoid": [
            "Do not pay recruitment, registration, security deposit, or laptop fees",
            "Do not share bank account login credentials as part of a job application",
        ],
        "verification": [
            "Check the company's official website and verified recruitment channels.",
        ],
    },
    "courier": {
        "actions": [
            "Track shipments only through the courier's official tracking portal using your original tracking number",
        ],
        "avoid": [
            "Do not pay customs clearance or release fees requested via personal SMS or messaging apps",
            "Do not download APK or app files sent to 'reschedule delivery'",
        ],
        "verification": [
            "Use the official courier tracking website manually using the original consignment number.",
        ],
    },
    "impersonation": {
        "actions": [
            "Hang up and independently contact the official agency via verified public directory numbers",
        ],
        "avoid": [
            "Remember that law enforcement and judicial authorities never conduct 'digital arrests' over video calls or demand immediate settlement payments",
        ],
        "verification": [
            "Verify official badge credentials and warrant claims directly with the local police station or department.",
        ],
    },
    "romance": {
        "actions": [
            "Perform reverse image searches on profile photographs to check for stolen identities",
        ],
        "avoid": [
            "Never send money, gift cards, or cryptocurrency to individuals you have not met in person",
        ],
        "verification": [
            "Insist on meeting in a safe public setting or via live verified video before discussing any personal matters.",
        ],
    },
    "deepfake": {
        "actions": [
            "Verify the person's identity through another independent communication channel (call, SMS, in-person)",
            "Observe the video closely for unnatural blinking, mouth-voice desync, or edge blurring",
        ],
        "avoid": [
            "Do not trust video or visual media alone as definitive proof of identity or distress",
        ],
        "verification": [
            "Confirm the person's identity through another communication channel.",
        ],
    },
    "voice": {
        "actions": [
            "Independently call the person or organization back using a trusted, saved phone number",
            "Ask a private question only the real person would know to confirm identity",
        ],
        "avoid": [
            "Do not trust caller identity solely from voice or caller ID display",
            "Never share OTP, PIN, or passwords during an incoming call",
        ],
        "verification": [
            "Call the person back using a known phone number.",
        ],
    },
    "url": {
        "actions": [
            "Navigate to the legitimate website by manually typing the official domain into your browser address bar",
        ],
        "avoid": [
            "Do not click on shortened, IP-based, or misspelled website links",
            "Do not enter passwords, credit card numbers, or personal info on unverified web pages",
        ],
        "verification": [
            "Inspect the domain name carefully in the address bar for spoofed spellings or unverified extensions.",
        ],
    },
}


def _detect_categories(analysis_result: Dict[str, Any]) -> Set[str]:
    """Identify scam categories present in the analysis result."""
    cats = set()
    raw_texts: List[str] = []

    # Gather category clues from signals
    if isinstance(analysis_result.get("signals"), list):
        for s in analysis_result["signals"]:
            if isinstance(s, dict):
                raw_texts.append(str(s.get("type", "")))
                raw_texts.append(str(s.get("evidence", "")))
            elif isinstance(s, str):
                raw_texts.append(s)

    # From indicators, evidence, modalities
    for key in ["indicators", "evidence", "modalities_used", "all_indicators"]:
        val = analysis_result.get(key)
        if isinstance(val, list):
            raw_texts.extend(str(item) for item in val)

    # From nested analysis
    if isinstance(analysis_result.get("analysis"), dict):
        for k in ["indicators", "prediction", "scam_type", "detected_category"]:
            v = analysis_result["analysis"].get(k)
            if v:
                raw_texts.append(str(v))

    # Modality-specific category hints
    input_type = analysis_result.get("modality") or analysis_result.get("input_type")
    if input_type == "url":
        cats.add("url")
    elif input_type == "audio":
        cats.add("voice")
    elif input_type == "video":
        cats.add("deepfake")

    combined_text = " ".join(raw_texts).lower()

    if "upi" in combined_text or "collect request" in combined_text:
        cats.add("upi")
    if any(k in combined_text for k in ["otp", "credential", "password", "pin", "cvv"]):
        cats.add("otp")
    if any(k in combined_text for k in ["kyc", "aadhaar", "pan card", "identity verification"]):
        cats.add("kyc")
    if any(k in combined_text for k in ["bank", "sbi", "hdfc", "icici", "axis", "rbi", "account blocked"]):
        cats.add("banking")
    if any(k in combined_text for k in ["invest", "crypto", "bitcoin", "forex", "trading", "high return", "guaranteed return"]):
        cats.add("investment")
    if any(k in combined_text for k in ["job", "recruitment", "part time", "salary", "hiring"]):
        cats.add("job")
    if any(k in combined_text for k in ["courier", "parcel", "fedex", "dhl", "customs", "delivery"]):
        cats.add("courier")
    if any(k in combined_text for k in ["impersonat", "police", "cbi", "arrest", "court", "customs officer"]):
        cats.add("impersonation")
    if any(k in combined_text for k in ["romance", "dating", "relationship"]):
        cats.add("romance")
    if any(k in combined_text for k in ["deepfake", "face manipulation", "synthetic video"]):
        cats.add("deepfake")
    if any(k in combined_text for k in ["voice clone", "voice spoof", "audio clone"]):
        cats.add("voice")
    if any(k in combined_text for k in ["phishing", "suspicious url", "malicious url", "http://", "tinyurl", "bit.ly"]):
        cats.add("url")

    return cats


def generate_actions(analysis_result: Dict[str, Any]) -> Dict[str, List[str]]:
    """
    Generate actionable advice based on risk level, categories, and evidence.

    Returns:
        {
            "immediate_actions": list[str],
            "avoid": list[str],
            "verification_steps": list[str]
        }
    """
    if not isinstance(analysis_result, dict):
        return {
            "immediate_actions": ["Continue with caution", "Verify the sender independently"],
            "avoid": ["Do not share sensitive information without verification"],
            "verification_steps": ["Open the official app/website manually instead of using provided links."],
        }

    # Extract score and level
    risk_score = analysis_result.get("risk_score")
    if risk_score is None:
        risk_score = analysis_result.get("final_score")
    if risk_score is None and isinstance(analysis_result.get("risk_assessment"), dict):
        risk_score = analysis_result["risk_assessment"].get("final_score")
    try:
        risk_score = int(risk_score) if risk_score is not None else 0
    except (ValueError, TypeError):
        risk_score = 0

    risk_level = analysis_result.get("risk_level")
    if not risk_level and isinstance(analysis_result.get("risk_assessment"), dict):
        risk_level = analysis_result["risk_assessment"].get("risk_level")
    if not risk_level:
        if risk_score >= 80:
            risk_level = "CRITICAL"
        elif risk_score >= 60:
            risk_level = "HIGH"
        elif risk_score >= 35:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
    risk_level = str(risk_level).upper()

    immediate_actions: List[str] = []
    avoid: List[str] = []
    verification_steps: List[str] = []

    # 1. Base Rules by Risk Level
    if risk_level == "CRITICAL":
        immediate_actions.extend([
            "Stop interacting with the sender immediately",
            "Do not click any links",
            "Do not provide OTP, PIN, password, KYC or banking information",
            "Contact the relevant bank/service through an independently verified official channel",
            "If financial loss has occurred, report the incident through the appropriate official cybercrime channel",
        ])
        avoid.extend([
            "Do not continue the conversation",
            "Do not transfer additional money",
            "Do not share authentication codes",
            "Do not install remote-access applications",
        ])
    elif risk_level == "HIGH":
        immediate_actions.extend([
            "Do not click suspicious links",
            "Do not reply with sensitive information",
            "Verify the claim through the organization's official website or phone number",
            "If money or credentials were already shared, contact the relevant bank/service immediately",
        ])
        avoid.extend([
            "Do not share OTP",
            "Do not share PIN",
            "Do not share passwords",
            "Do not install unknown applications",
            "Do not transfer money",
        ])
    elif risk_level == "MEDIUM":
        immediate_actions.extend([
            "Verify the sender using an official channel",
            "Avoid clicking unknown links",
            "Do not share OTP or passwords",
        ])
        avoid.extend([
            "Do not transfer money until independently verified",
        ])
    else:  # LOW
        immediate_actions.extend([
            "Continue with caution",
            "Verify the sender independently",
        ])
        avoid.extend([
            "Do not share sensitive information without verification",
        ])

    # 2. Category-Specific Action & Avoid Enhancements
    categories = _detect_categories(analysis_result)
    for cat in categories:
        rules = CATEGORY_RULES.get(cat)
        if rules:
            for act in rules["actions"]:
                if act not in immediate_actions:
                    immediate_actions.append(act)
            for av in rules["avoid"]:
                if av not in avoid:
                    avoid.append(av)
            for v in rules["verification"]:
                if v not in verification_steps:
                    verification_steps.append(v)

    # 3. Standard Verification Steps
    default_verification = [
        "Open the official app or website manually rather than following supplied links.",
        "Contact the organization using independently obtained phone numbers from official websites.",
        "Do not use contact information or callback numbers supplied by the suspicious message.",
    ]
    for step in default_verification:
        if step not in verification_steps:
            verification_steps.append(step)

    # Deduplicate while preserving order
    immediate_actions = list(dict.fromkeys(immediate_actions))
    avoid = list(dict.fromkeys(avoid))
    verification_steps = list(dict.fromkeys(verification_steps))

    return {
        "immediate_actions": immediate_actions,
        "avoid": avoid,
        "verification_steps": verification_steps,
    }
