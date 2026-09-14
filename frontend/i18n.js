/**
 * SatyaAI 3.0 — Multi-Language Localization (i18n)
 * Supports English (en), Hindi (hi), and Marathi (mr)
 */

const translations = {
  en: {
    // Header & Meta
    "header.badge": "Live Intelligence",
    "header.theme_dark": "Dark",
    "header.theme_light": "Light",
    "header.copilot": "AI Copilot",
    "lang.select_title": "Choose Language",

    // SOC Navigation
    "nav.dashboard": "Dashboard",
    "nav.detection": "Threat Detection",
    "nav.email": "Email Analysis",
    "nav.call": "Call Analysis",
    "nav.media": "Image & Video Scan",
    "nav.url": "URL Analysis",
    "nav.geo": "Geolocation Tracking",
    "nav.risk": "Risk Scoring",
    "nav.reports": "Threat Reports",
    "nav.copilot": "AI Threat Assistant",
    "nav.settings": "Settings",
    "nav.status_operational": "All systems operational",
    "nav.analyst_role": "Cyber Defense Analyst",
    "nav.search_placeholder": "Search threats, IPs, domains, files...",

    // SOC Dashboard
    "dash.hero_title": "Detect • Analyze • Protect",
    "dash.hero_subtitle": "AI-powered cybersecurity platform to detect, analyze and prevent digital threats in real time.",
    "dash.kpi_total": "Total Threats Detected",
    "dash.kpi_email": "Email Threats",
    "dash.kpi_call": "Call Threats",
    "dash.kpi_url": "Malicious URLs",
    "dash.kpi_media": "Image / Video Threats",
    "dash.kpi_risk": "System Risk Score",
    "dash.quick_actions": "Quick Threat Actions",
    "dash.action_scan_file": "Scan File / Image",
    "dash.action_check_url": "Check URL",
    "dash.action_analyze_email": "Analyze Email",
    "dash.action_analyze_call": "Analyze Call",
    "dash.action_track_geo": "Track Location",
    "dash.chart_title": "Threat Activity Overview",
    "dash.distribution_title": "Threat Types Distribution",
    "dash.recent_threats_title": "Recent Threats Feed",
    "dash.recent_analysis_title": "Recent Analysis Records",
    "dash.empty_chart": "No historical threat data available",
    "dash.empty_threats": "No threats detected in this session yet",
    "dash.empty_analysis": "No analysis records available. Run a scan above to start building threat intelligence.",
    "dash.no_data": "No data available",
    "dash.risk_unavailable": "Risk score unavailable",

    // Hero Section
    "hero.badge": "CYBER THREAT DEFENSE PLATFORM",
    "hero.title_pre": "SATYA",
    "hero.title_ai": "AI",
    "hero.title_defense": "Defense",
    "hero.title_sub": "& Deepfake Intelligence",
    "hero.subtitle": "Multimodal cyber fraud & deepfake intelligence. Real-time detection across scam messages, phishing URLs, image screenshots, audio voice clones, and video deepfakes.",

    // Tabs
    "tab.message": "Message",
    "tab.url": "URL",
    "tab.email": "Email Threat",
    "tab.call": "Call Threat",
    "tab.image": "Image",
    "tab.audio": "Audio",
    "tab.video": "Video",
    "tab.copilot": "Copilot",

    // Email Panel
    "email.title": "Analyze email for phishing & spoofing",
    "email.subject_label": "Email Subject",
    "email.subject_placeholder": "e.g. URGENT: Your bank account will be suspended",
    "email.sender_label": "Sender Email (Optional)",
    "email.sender_placeholder": "e.g. security@sbi-update-kyc.com",
    "email.body_label": "Email Body Content",
    "email.body_placeholder": "Paste email text here, or upload an .eml file below...",
    "email.drop_title": "Or upload an .eml email file",
    "email.drop_hint": ".eml, .msg, .txt supported",
    "email.samples_label": "Try samples:",
    "email.sample_phish": "Phishing Email",
    "email.sample_safe": "Legitimate Email",
    "email.btn_analyze": "Analyze Email Threat",

    // Call Panel
    "call.title": "Upload audio call recording or paste transcript",
    "call.audio_drop_title": "Upload Call Recording Audio",
    "call.audio_drop_hint": "MP3, WAV, M4A, OGG, WEBM supported",
    "call.transcript_label": "Or paste Call Conversation Transcript",
    "call.transcript_placeholder": "Hello, I am calling from your bank. Your account will be suspended today. Please provide your OTP immediately...",
    "call.samples_label": "Try samples:",
    "call.sample_scam": "Scam Call Sample",
    "call.sample_safe": "Safe Call Sample",
    "call.btn_analyze": "Analyze Call Threat",

    // Message Panel
    "message.label": "Paste the suspicious message below",
    "message.placeholder": "URGENT: Your SBI account has been suspended due to KYC non-compliance. Click here immediately to verify: http://sbi-kyc-update.ru/verify?id=...",
    "message.samples_label": "Try samples:",
    "message.sample_scam": "Scam Sample",
    "message.sample_safe": "Safe Sample",
    "message.btn_analyze": "Analyze Message",

    // URL Panel
    "url.label": "Enter the suspicious URL",
    "url.placeholder": "http://192.168.1.1/paypal-login-verify?token=abc123",
    "url.samples_label": "Try samples:",
    "url.sample_phish": "Phishing URL",
    "url.sample_safe": "Safe URL",
    "url.btn_analyze": "Analyze URL",

    // Image Panel
    "image.title": "Drop a screenshot or scam image here",
    "image.hint": "PNG, JPG, WEBP, BMP supported",
    "image.btn_choose": "Choose File",
    "image.btn_analyze": "Analyze Image",

    // Audio Panel
    "audio.title": "Upload a suspicious audio call recording",
    "audio.hint": "MP3, WAV, M4A, OGG, FLAC supported",
    "audio.btn_choose": "Choose File",
    "audio.btn_analyze": "Analyze Audio",

    // Video Panel
    "video.title": "Upload a suspicious video for deepfake analysis",
    "video.hint": "MP4, MOV, AVI, MKV, WEBM supported",
    "video.btn_choose": "Choose File",
    "video.btn_analyze": "Analyze Video",

    // Scanning Radar Overlay
    "radar.badge": "SATYAAI MULTIMODAL INFERENCE",
    "radar.title": "Analyzing Threat Telemetry...",
    "radar.subtitle": "Extracting feature vectors & checking neural fraud indicators",
    "radar.step1": "Deconstructing input streams across neural inspection layers...",
    "radar.step2": "Extracting latent feature embeddings & acoustic spectra...",
    "radar.step3": "Scanning against 100,000+ known cybercrime signatures...",
    "radar.step4": "Evaluating semantic, phonetic & visual fraud indicators...",
    "radar.step5": "Synthesizing cross-modality cyber risk matrix...",

    // Modal / Threat Dossier
    "modal.badge": "LIVE THREAT INTELLIGENCE REPORT",
    "modal.title": "Analysis Verdict & Threat Dossier",
    "modal.btn_copy": "Copy Report",
    "modal.btn_copied": "Copied!",
    "modal.btn_print": "Print",
    "modal.score_title_scam": "Scam Risk Score",
    "modal.score_title_deepfake": "Deepfake Risk Score",
    "modal.score_label": "/ 100",
    "modal.verdict_title": "🛡️ AI Verdict & Recommended Action",
    "modal.indicators_title": "⚠️ Detected Threat Indicators",
    "modal.why_suspicious_title": "Why is this Suspicious?",
    "modal.attacker_goals_title": "What May the Attacker Want?",
    "modal.actions_do_title": "What Should You Do?",
    "modal.actions_avoid_title": "Do Not Do This",
    "modal.verification_title": "How to Verify",
    "modal.no_indicators": "✅ No significant threat indicators detected",
    "modal.telemetry_title": "Technical Telemetry & Raw Model JSON",
    "modal.footer_hint": "Press ESC or click backdrop to dismiss",
    "modal.btn_close": "Close Dossier",
    "modal.transcript_audio": "🎙️ Audio Transcript",
    "modal.transcript_ocr": "📝 OCR Extracted Text",
    "modal.transcript_video": "🎬 Video Forensic Telemetry",
    "modal.transcript_url": "🌐 URL & Geolocation Intelligence",
    "modal.transcript_email": "📧 Email Forensic Dossier & Header Intelligence",
    "modal.transcript_call": "📞 Call Threat Telemetry & Behavioral Signals",
    "modal.score_title_email": "Email Phishing Threat Score",
    "modal.score_title_call": "Call Scam Risk Score",
    "modal.btn_copilot": "Investigate in Copilot",

    // Copilot
    "copilot.fab_title": "AI Copilot",
    "copilot.fab_badge": "RAG Active",
    "copilot.title": "AI Fraud Investigation Copilot",
    "copilot.subtitle": "Autonomous RAG threat intelligence & multimodal investigation assistant",
    "copilot.badge_active": "Active Evidence Dossier:",
    "copilot.badge_general": "Mode: General Cyber Threat Knowledge Base",
    "copilot.btn_clear_evidence": "✕ Clear Evidence",
    "copilot.upload_heading": "Attach Evidence to Copilot",
    "copilot.upload_type_text": "💬 Text / SMS",
    "copilot.upload_type_url": "🔗 URL Link",
    "copilot.upload_type_file": "📁 File (Media)",
    "copilot.upload_text_placeholder": "Paste suspicious message, SMS, email text, or chat transcript...",
    "copilot.upload_url_placeholder": "Enter suspicious URL or domain (e.g. http://sbi-kyc-verify.ru)...",
    "copilot.upload_file_drop": "Drop screenshot, audio recording, or video deepfake here",
    "copilot.upload_btn_submit": "Analyze & Attach to Copilot",
    "copilot.chips_heading": "Quick Investigation Questions:",
    "copilot.chip_why": "Why is this suspicious?",
    "copilot.chip_type": "What type of scam is this?",
    "copilot.chip_redflags": "What are the red flags?",
    "copilot.chip_goal": "What is the attacker trying to steal?",
    "copilot.chip_action": "What should I do now?",
    "copilot.chip_report": "How do I report this scam?",
    "copilot.chat_welcome": "Hello! I am your **SATYA AI Fraud Investigation Copilot**. You can ask me questions about any uploaded evidence (text, URLs, screenshots, audio, or video), or ask general questions about cyber scams, banking fraud, UPI traps, and digital safety.",
    "copilot.input_placeholder": "Ask Copilot anything about this threat or cyber scams (Press Enter)...",
    "copilot.btn_send": "Send",
    "copilot.thinking": "Consulting threat intelligence and synthesizing response...",
    "copilot.sources_title": "Grounding Sources & Threat Intelligence:",

    // Risk Levels
    "risk.low": "LOW",
    "risk.medium": "MEDIUM",
    "risk.high": "HIGH",
    "risk.critical": "CRITICAL",

    // History & Footer
    "history.title": "Analysis History",
    "history.empty": "No analysis performed in this session yet.",
    "footer.rights": "SATYA AI 3.0 © 2026 — Multimodal Cyber Intelligence Platform",
    "footer.note": "For educational & hackathon demonstration purposes.",
  },

  hi: {
    // Header & Meta
    "header.badge": "सक्रिय इंटेलिजेंस",
    "header.theme_dark": "डार्क",
    "header.theme_light": "लाइट",
    "header.copilot": "एआई कोपायलट",
    "lang.select_title": "भाषा चुनें",

    // SOC Navigation
    "nav.dashboard": "डैशबोर्ड",
    "nav.detection": "खतरा पहचान",
    "nav.email": "ईमेल विश्लेषण",
    "nav.call": "कॉल विश्लेषण",
    "nav.media": "इमेज और वीडियो स्कैन",
    "nav.url": "यूआरएल विश्लेषण",
    "nav.geo": "स्थान ट्रैकिंग",
    "nav.risk": "जोखिम स्कोरिंग",
    "nav.reports": "खतरा रिपोर्ट्स",
    "nav.copilot": "एआई खतरा सहायक",
    "nav.settings": "सेटिंग्स",
    "nav.status_operational": "सभी प्रणालियां सक्रिय हैं",
    "nav.analyst_role": "साइबर सुरक्षा विश्लेषक",
    "nav.search_placeholder": "खतरे, आईपी, डोमेन, फ़ाइलें खोजें...",

    // SOC Dashboard
    "dash.hero_title": "पहचान • विश्लेषण • सुरक्षा",
    "dash.hero_subtitle": "डिजिटल खतरों को वास्तविक समय में पहचानने, विश्लेषण करने और रोकने के लिए एआई साइबर सुरक्षा मंच।",
    "dash.kpi_total": "कुल पहचाने गए खतरे",
    "dash.kpi_email": "ईमेल खतरे",
    "dash.kpi_call": "कॉल खतरे",
    "dash.kpi_url": "दुर्भावनापूर्ण यूआरएल",
    "dash.kpi_media": "इमेज / वीडियो खतरे",
    "dash.kpi_risk": "सिस्टम जोखिम स्कोर",
    "dash.quick_actions": "त्वरित खतरा क्रियाएं",
    "dash.action_scan_file": "फ़ाइल / छवि स्कैन",
    "dash.action_check_url": "यूआरएल जांचें",
    "dash.action_analyze_email": "ईमेल विश्लेषण",
    "dash.action_analyze_call": "कॉल विश्लेषण",
    "dash.action_track_geo": "स्थान ट्रैक करें",
    "dash.chart_title": "खतरा गतिविधि अवलोकन",
    "dash.distribution_title": "खतरा प्रकार वितरण",
    "dash.recent_threats_title": "हालिया खतरे",
    "dash.recent_analysis_title": "हालिया विश्लेषण रिकॉर्ड",
    "dash.empty_chart": "कोई ऐतिहासिक खतरा डेटा उपलब्ध नहीं है",
    "dash.empty_threats": "इस सत्र में अभी तक कोई खतरा नहीं मिला",
    "dash.empty_analysis": "कोई विश्लेषण रिकॉर्ड उपलब्ध नहीं है। इंटेलिजेंस एकत्र करने के लिए ऊपर स्कैन करें।",
    "dash.no_data": "डेटा उपलब्ध नहीं है",
    "dash.risk_unavailable": "जोखिम स्कोर अनुपलब्ध",

    // Hero Section
    "hero.badge": "साइबर खतरा सुरक्षा मंच",
    "hero.title_pre": "सत्य",
    "hero.title_ai": "AI",
    "hero.title_defense": "सुरक्षा",
    "hero.title_sub": "& डीपफेक इंटेलिजेंस",
    "hero.subtitle": "मल्टीमॉडल साइबर धोखाधड़ी और डीपफेक इंटेलिजेंस। स्कैम संदेशों, फ़िशिंग यूआरएल, इमेज स्क्रीनशॉट, ऑडियो वॉयस क्लोन और वीडियो डीपफेक की त्वरित एवं सटीक पहचान।",

    // Tabs
    "tab.message": "संदेश",
    "tab.url": "यूआरएल",
    "tab.email": "ईमेल थ्रेट",
    "tab.call": "कॉल थ्रेट",
    "tab.image": "इमेज",
    "tab.audio": "ऑडियो",
    "tab.video": "वीडियो",
    "tab.copilot": "कॉपायलट",

    // Email Panel
    "email.title": "फ़िशिंग और स्पूफिंग के लिए ईमेल का विश्लेषण करें",
    "email.subject_label": "ईमेल विषय (Subject)",
    "email.subject_placeholder": "उदा. URGENT: Your bank account will be suspended",
    "email.sender_label": "प्रेषक ईमेल (वैकल्पिक)",
    "email.sender_placeholder": "उदा. security@sbi-update-kyc.com",
    "email.body_label": "ईमेल सामग्री (Body)",
    "email.body_placeholder": "ईमेल का पाठ यहाँ पेस्ट करें, या नीचे .eml फ़ाइल अपलोड करें...",
    "email.drop_title": "या यहाँ .eml ईमेल फ़ाइल अपलोड करें",
    "email.drop_hint": ".eml, .msg, .txt समर्थित",
    "email.samples_label": "नमूने आजमाएं:",
    "email.sample_phish": "फ़िशिंग ईमेल",
    "email.sample_safe": "सुरक्षित ईमेल",
    "email.btn_analyze": "ईमेल थ्रेट का विश्लेषण करें",

    // Call Panel
    "call.title": "कॉल रिकॉर्डिंग ऑडियो अपलोड करें या ट्रांसक्रिप्ट पेस्ट करें",
    "call.audio_drop_title": "कॉल रिकॉर्डिंग ऑडियो अपलोड करें",
    "call.audio_drop_hint": "MP3, WAV, M4A, OGG, WEBM समर्थित",
    "call.transcript_label": "या कॉल ट्रांसक्रिप्ट यहाँ पेस्ट करें",
    "call.transcript_placeholder": "नमस्ते, मैं आपके बैंक से बोल रहा हूँ। आपका खाता आज बंद हो जाएगा। कृपया तुरंत अपना OTP दें...",
    "call.samples_label": "नमूने आजमाएं:",
    "call.sample_scam": "स्कैम कॉल नमूना",
    "call.sample_safe": "सुरक्षित कॉल नमूना",
    "call.btn_analyze": "कॉल थ्रेट का विश्लेषण करें",

    // Message Panel
    "message.label": "नीचे संदिग्ध संदेश पेस्ट करें",
    "message.placeholder": "अति आवश्यक: आपका बैंक खाता केवाईसी न होने के कारण बंद कर दिया गया है। तुरंत सत्यापित करने के लिए यहाँ क्लिक करें: http://sbi-kyc-update.ru/verify...",
    "message.samples_label": "नमूने आजमाएं:",
    "message.sample_scam": "स्कैम नमूना",
    "message.sample_safe": "सुरक्षित नमूना",
    "message.btn_analyze": "संदेश का विश्लेषण करें",

    // URL Panel
    "url.label": "संदिग्ध यूआरएल दर्ज करें",
    "url.placeholder": "http://192.168.1.1/paypal-login-verify?token=abc123",
    "url.samples_label": "नमूने आजमाएं:",
    "url.sample_phish": "फ़िशिंग यूआरएल",
    "url.sample_safe": "सुरक्षित यूआरएल",
    "url.btn_analyze": "यूआरएल का विश्लेषण करें",

    // Image Panel
    "image.title": "संदिग्ध स्क्रीनशॉट या स्कैम इमेज यहाँ छोड़ें",
    "image.hint": "PNG, JPG, WEBP, BMP समर्थित",
    "image.btn_choose": "फ़ाइल चुनें",
    "image.btn_analyze": "इमेज का विश्लेषण करें",

    // Audio Panel
    "audio.title": "संदिग्ध ऑडियो कॉल या वॉयस नोट अपलोड करें",
    "audio.hint": "MP3, WAV, M4A, OGG, FLAC समर्थित",
    "audio.btn_choose": "फ़ाइल चुनें",
    "audio.btn_analyze": "ऑडियो का विश्लेषण करें",

    // Video Panel
    "video.title": "डीपफेक जांच के लिए संदिग्ध वीडियो अपलोड करें",
    "video.hint": "MP4, MOV, AVI, MKV, WEBM समर्थित",
    "video.btn_choose": "फ़ाइल चुनें",
    "video.btn_analyze": "वीडियो का विश्लेषण करें",

    // Scanning Radar Overlay
    "radar.badge": "सत्य AI मल्टीमॉडल न्यूरल विश्लेषण",
    "radar.title": "साइबर थ्रेट टेलीमेट्री का विश्लेषण जारी है...",
    "radar.subtitle": "फीचर वेक्टर्स निकाले जा रहे हैं और फ्रॉड संकेतकों की जांच हो रही है",
    "radar.step1": "न्यूरल इंस्पेक्शन लेयर्स द्वारा इनपुट स्ट्रीम्स का विश्लेषण...",
    "radar.step2": "लेटेंट फीचर एम्बेडिंग और स्पेक्ट्रल प्रोफाइल का निष्कर्षण...",
    "radar.step3": "100,000+ ज्ञात साइबर क्राइम डेटाबेस के साथ मिलान...",
    "radar.step4": "अर्थगत, ध्वन्यात्मक और दृश्य फ्रॉड संकेतकों का मूल्यांकन...",
    "radar.step5": "क्रॉस-मोडैलिटी साइबर रिस्क मैट्रिक्स का संकलन...",

    // Modal / Threat Dossier
    "modal.badge": "लाइव थ्रेट इंटेलिजेंस रिपोर्ट",
    "modal.title": "विश्लेषण निष्कर्ष और थ्रेट डॉसियर",
    "modal.btn_copy": "रिपोर्ट कॉपी करें",
    "modal.btn_copied": "कॉपी हो गया!",
    "modal.btn_print": "प्रिंट करें",
    "modal.score_title_scam": "स्कैम जोखिम स्कोर",
    "modal.score_title_deepfake": "डीपफेक जोखिम स्कोर",
    "modal.score_label": "/ 100",
    "modal.verdict_title": "🛡️ AI निष्कर्ष और अनुशंसित कार्रवाई",
    "modal.indicators_title": "⚠️ पहचाने गए खतरे के संकेतक",
    "modal.why_suspicious_title": "यह संदिग्ध क्यों है?",
    "modal.attacker_goals_title": "हमलावर क्या हासिल करना चाहता है?",
    "modal.actions_do_title": "आपको क्या करना चाहिए?",
    "modal.actions_avoid_title": "यह बिल्कुल न करें",
    "modal.verification_title": "सत्यापन कैसे करें",
    "modal.no_indicators": "✅ कोई महत्वपूर्ण खतरा संकेतक नहीं पाया गया",
    "modal.telemetry_title": "तकनीकी टेलीमेट्री और रॉ मॉडल JSON",
    "modal.footer_hint": "बंद करने के लिए ESC दबाएं या बाहर क्लिक करें",
    "modal.btn_close": "डॉसियर बंद करें",
    "modal.transcript_audio": "🎙️ ऑडियो ट्रांसक्रिप्ट",
    "modal.transcript_ocr": "📝 निकाला गया टेक्स्ट (OCR)",
    "modal.transcript_video": "🎬 वीडियो फॉरेंसिक टेलीमेट्री",
    "modal.transcript_url": "🌐 यूआरएल एवं जियोलोकेशन इंटेलिजेंस",
    "modal.transcript_email": "📧 ईमेल फॉरेंसिक डॉसियर एवं हेडर इंटेलिजेंस",
    "modal.transcript_call": "📞 कॉल थ्रेट टेलीमेट्री एवं व्यवहार संकेत",
    "modal.score_title_email": "ईमेल फ़िशिंग खतरा स्कोर",
    "modal.score_title_call": "वॉयस कॉल स्कैम जोखिम स्कोर",
    "modal.btn_copilot": "कॉपायलट में जांचें",

    // Copilot
    "copilot.fab_title": "AI कॉपायलट",
    "copilot.fab_badge": "RAG सक्रिय",
    "copilot.title": "AI फ्रॉड इन्वेस्टिगेशन कॉपायलट",
    "copilot.subtitle": "RAG थ्रेट इंटेलिजेंस और मल्टीमॉडल साइबर जांच सहायक",
    "copilot.badge_active": "सक्रिय साक्ष्य डॉसियर:",
    "copilot.badge_general": "मोड: सामान्य साइबर अपराध ज्ञानकोश",
    "copilot.btn_clear_evidence": "✕ साक्ष्य हटाएं",
    "copilot.upload_heading": "कॉपायलट में साक्ष्य जोड़ें",
    "copilot.upload_type_text": "💬 संदेश / SMS",
    "copilot.upload_type_url": "🔗 यूआरएल लिंक",
    "copilot.upload_type_file": "📁 फ़ाइल (मीडिया)",
    "copilot.upload_text_placeholder": "संदिग्ध संदेश, ईमेल या चैट यहाँ पेस्ट करें...",
    "copilot.upload_url_placeholder": "संदिग्ध लिंक या वेबसाइट दर्ज करें...",
    "copilot.upload_file_drop": "स्क्रीनशॉट, ऑडियो कॉल या वीडियो यहाँ छोड़ें",
    "copilot.upload_btn_submit": "विश्लेषण करें और कॉपायलट से जोड़ें",
    "copilot.chips_heading": "त्वरित जांच प्रश्न:",
    "copilot.chip_why": "यह संदेहास्पद क्यों है?",
    "copilot.chip_type": "यह किस प्रकार का स्कैम है?",
    "copilot.chip_redflags": "खतरे के मुख्य संकेत क्या हैं?",
    "copilot.chip_goal": "धोखेबाज क्या चुराने की कोशिश कर रहा है?",
    "copilot.chip_action": "मुझे तुरंत क्या कदम उठाने चाहिए?",
    "copilot.chip_report": "इस स्कैम की शिकायत कैसे दर्ज करें?",
    "copilot.chat_welcome": "नमस्ते! मैं आपका **सत्य AI फ्रॉड इन्वेस्टिगेशन कॉपायलट** हूँ। आप मुझसे किसी भी साक्ष्य (संदेश, यूआरएल, स्क्रीनशॉट, ऑडियो, या वीडियो) के बारे में पूछ सकते हैं, या साइबर अपराध, यूपीआई फ्रॉड और ऑनलाइन सुरक्षा से जुड़े सामान्य सवाल पूछ सकते हैं।",
    "copilot.input_placeholder": "इस खतरे या साइबर फ्रॉड के बारे में कुछ भी पूछें...",
    "copilot.btn_send": "भेजें",
    "copilot.thinking": "थ्रेट डेटाबेस की जांच और विश्लेषण जारी है...",
    "copilot.sources_title": "संदर्भ स्रोत और थ्रेट इंटेलिजेंस:",

    // Risk Levels
    "risk.low": "कम (LOW)",
    "risk.medium": "मध्यम (MEDIUM)",
    "risk.high": "उच्च (HIGH)",
    "risk.critical": "गंभीर (CRITICAL)",

    // History & Footer
    "history.title": "विश्लेषण इतिहास",
    "history.empty": "इस सत्र में अभी तक कोई विश्लेषण नहीं किया गया।",
    "footer.rights": "सत्य AI 3.0 © 2026 — मल्टीमॉडल साइबर इंटेलिजेंस प्लेटफॉर्म",
    "footer.note": "शैक्षणिक और हैकाथॉन प्रदर्शन उद्देश्यों के लिए।",
  },

  mr: {
    // Header & Meta
    "header.badge": "सक्रिय बुद्धिमत्ता",
    "header.theme_dark": "डार्क",
    "header.theme_light": "लाइट",
    "header.copilot": "एआय कोपायलट",
    "lang.select_title": "भाषा निवडा",

    // SOC Navigation
    "nav.dashboard": "डॅशबोर्ड",
    "nav.detection": "धोका शोध",
    "nav.email": "ईमेल विश्लेषण",
    "nav.call": "कॉल विश्लेषण",
    "nav.media": "इमेज आणि व्हिडिओ स्कॅन",
    "nav.url": "यूआरएल विश्लेषण",
    "nav.geo": "स्थान ट्रॅकिंग",
    "nav.risk": "जोखीम स्कोअरिंग",
    "nav.reports": "धोका अहवाल",
    "nav.copilot": "एआय धोका सहाय्यक",
    "nav.settings": "सेटिंग्ज",
    "nav.status_operational": "सर्व प्रणाली कार्यरत आहेत",
    "nav.analyst_role": "सायबर सुरक्षा विश्लेषक",
    "nav.search_placeholder": "धोके, आयपी, डोमेन, फाइल्स शोधा...",

    // SOC Dashboard
    "dash.hero_title": "शोध • विश्लेषण • संरक्षण",
    "dash.hero_subtitle": "डिजिटल धोके रिअल-टाइममध्ये शोधण्यासाठी, विश्लेषित करण्यासाठी आणि रोखण्यासाठी एआय सायबर सुरक्षा प्लॅटफॉर्म.",
    "dash.kpi_total": "एकूण शोधलेले धोके",
    "dash.kpi_email": "ईमेल धोके",
    "dash.kpi_call": "कॉल धोके",
    "dash.kpi_url": "धोकादायक यूआरएल",
    "dash.kpi_media": "इमेज / व्हिडिओ धोके",
    "dash.kpi_risk": "सिस्टम जोखीम स्कोअर",
    "dash.quick_actions": "त्वरित कृती",
    "dash.action_scan_file": "फाइल / इमेज स्कॅन",
    "dash.action_check_url": "यूआरएल तपासा",
    "dash.action_analyze_email": "ईमेल विश्लेषण",
    "dash.action_analyze_call": "कॉल विश्लेषण",
    "dash.action_track_geo": "स्थान ट्रॅक करा",
    "dash.chart_title": "धोका क्रियाकलाप आढावा",
    "dash.distribution_title": "धोका प्रकार वितरण",
    "dash.recent_threats_title": "नुकतेच आढळलेले धोके",
    "dash.recent_analysis_title": "नुकतेच विश्लेषण केलेले रेकॉर्ड",
    "dash.empty_chart": "कोणताही ऐतिहासिक धोका डेटा उपलब्ध नाही",
    "dash.empty_threats": "या सत्रात अद्याप कोणताही धोका आढळला नाही",
    "dash.empty_analysis": "कोणतेही विश्लेषण रेकॉर्ड उपलब्ध नाही. माहिती गोळा करण्यासाठी वर स्कॅन करा.",
    "dash.no_data": "माहिती उपलब्ध नाही",
    "dash.risk_unavailable": "जोखीम स्कोअर अनुपलब्ध",

    // Hero Section
    "hero.badge": "सायबर धोका सुरक्षा व्यासपीठ",
    "hero.title_pre": "सत्य",
    "hero.title_ai": "AI",
    "hero.title_defense": "संरक्षण",
    "hero.title_sub": "& डीपफेक बुद्धिमत्ता",
    "hero.subtitle": "मल्टीमॉडल सायबर फसवणूक आणि डीपफेक बुद्धिमत्ता. फसव्या मेसेज, फिशिंग यूआरएल, इमेज स्क्रीनशॉट, ऑडिओ व्हॉइस क्लोन आणि व्हिडिओ डीपफेकची रिअल-टाइम तपासणी.",

    // Tabs
    "tab.message": "मेसेज",
    "tab.url": "यूआरएल",
    "tab.email": "ईमेल थ्रेट",
    "tab.call": "कॉल थ्रेट",
    "tab.image": "चित्र",
    "tab.audio": "ऑडिओ",
    "tab.video": "व्हिडिओ",
    "tab.copilot": "कॉपायलट",

    // Email Panel
    "email.title": "फिशिंग आणि स्पूफिंगसाठी ईमेलचे विश्लेषण करा",
    "email.subject_label": "ईमेल विषय (Subject)",
    "email.subject_placeholder": "उदा. URGENT: Your bank account will be suspended",
    "email.sender_label": "प्रेषक ईमेल (पर्यायी)",
    "email.sender_placeholder": "उदा. security@sbi-update-kyc.com",
    "email.body_label": "ईमेल मजकूर (Body)",
    "email.body_placeholder": "ईमेलचा मजकूर येथे पेस्ट करा, किंवा खाली .eml फाइल अपलोड करा...",
    "email.drop_title": "किंवा येथे .eml ईमेल फाइल अपलोड करा",
    "email.drop_hint": ".eml, .msg, .txt समर्थित",
    "email.samples_label": "नमुने तपासा:",
    "email.sample_phish": "फिशिंग ईमेल",
    "email.sample_safe": "सुरक्षित ईमेल",
    "email.btn_analyze": "ईमेल थ्रेटचे विश्लेषण करा",

    // Call Panel
    "call.title": "कॉल रेकॉर्डिंग ऑडिओ अपलोड करा किंवा संभाषण ट्रान्सक्रिप्ट पेस्ट करा",
    "call.audio_drop_title": "कॉल रेकॉर्डिंग ऑडिओ अपलोड करा",
    "call.audio_drop_hint": "MP3, WAV, M4A, OGG, WEBM समर्थित",
    "call.transcript_label": "किंवा संभाषण ट्रान्सक्रिप्ट येथे पेस्ट करा",
    "call.transcript_placeholder": "नमस्कार, मी तुमच्या बँकेतून बोलत आहे. तुमचे खाते आज निलंबित केले जाईल. कृपया त्वरित तुमचा OTP द्या...",
    "call.samples_label": "नमुने तपासा:",
    "call.sample_scam": "स्कॅम कॉल नमुना",
    "call.sample_safe": "सुरक्षित कॉल नमुना",
    "call.btn_analyze": "कॉल थ्रेटचे विश्लेषण करा",

    // Message Panel
    "message.label": "खाली संशयास्पद मेसेज पेस्ट करा",
    "message.placeholder": "तातडीचे: केवायसी न केल्यामुळे तुमचे बँक खाते तात्पुरते बंद केले आहे. त्वरित पडताळणी करण्यासाठी येथे क्लिक करा: http://sbi-kyc-update.ru/verify...",
    "message.samples_label": "नमुने तपासा:",
    "message.sample_scam": "स्कॅम नमुना",
    "message.sample_safe": "सुरक्षित नमुना",
    "message.btn_analyze": "मेसेजचे विश्लेषण करा",

    // URL Panel
    "url.label": "संशयास्पद यूआरएल प्रविष्ट करा",
    "url.placeholder": "http://192.168.1.1/paypal-login-verify?token=abc123",
    "url.samples_label": "नमुने तपासा:",
    "url.sample_phish": "फिशिंग यूआरएल",
    "url.sample_safe": "सुरक्षित यूआरएल",
    "url.btn_analyze": "यूआरएलचे विश्लेषण करा",

    // Image Panel
    "image.title": "स्क्रीनशॉट किंवा संशयास्पद इमेज येथे टाका",
    "image.hint": "PNG, JPG, WEBP, BMP समर्थित",
    "image.btn_choose": "फाइल निवडा",
    "image.btn_analyze": "इमेजचे विश्लेषण करा",

    // Audio Panel
    "audio.title": "संशयास्पद ऑडिओ कॉल किंवा व्हॉइस रेकॉर्डिंग अपलोड करा",
    "audio.hint": "MP3, WAV, M4A, OGG, FLAC समर्थित",
    "audio.btn_choose": "फाइल निवडा",
    "audio.btn_analyze": "ऑडिओचे विश्लेषण करा",

    // Video Panel
    "video.title": "डीपफेक तपासणीसाठी संशयास्पद व्हिडिओ अपलोड करा",
    "video.hint": "MP4, MOV, AVI, MKV, WEBM समर्थित",
    "video.btn_choose": "फाइल निवडा",
    "video.btn_analyze": "व्हिडिओचे विश्लेषण करा",

    // Scanning Radar Overlay
    "radar.badge": "सत्य AI मल्टीमॉडल न्यूरल विश्लेषण",
    "radar.title": "सायबर धोक्याच्या डेटाचे विश्लेषण सुरू आहे...",
    "radar.subtitle": "फीचर वेक्टर्स काढले जात आहेत आणि फ्रॉड निर्देशांकांची तपासणी सुरू आहे",
    "radar.step1": "न्यूरल तपासणी थरांद्वारे इनपुट डेटाचे विश्लेषण सुरू आहे...",
    "radar.step2": "ध्वनी व दृश्य वर्णपटातील लेटेंट वैशिष्ट्ये तपासली जात आहेत...",
    "radar.step3": "100,000+ नोंदणीकृत सायबर गुन्ह्यांच्या नमुन्यांशी पडताळणी...",
    "radar.step4": "शाब्दिक, ध्वन्यात्मक आणि दृश्य फसवणूक निर्देशकांचे मूल्यांकन...",
    "radar.step5": "मल्टीमॉडल सायबर रिस्क मॅट्रिक्सचे संकलन सुरू आहे...",

    // Modal / Threat Dossier
    "modal.badge": "लाइव्ह थ्रेट इंटेलिजन्स अहवाल",
    "modal.title": "विश्लेषण निष्कर्ष आणि थ्रेट अहवाल",
    "modal.btn_copy": "अहवाल कॉपी करा",
    "modal.btn_copied": "कॉपी झाले!",
    "modal.btn_print": "प्रिंट करा",
    "modal.score_title_scam": "स्कॅम धोका स्कोअर",
    "modal.score_title_deepfake": "डीपफेक धोका स्कोअर",
    "modal.score_label": "/ 100",
    "modal.verdict_title": "🛡️ AI निष्कर्ष आणि शिफारस केलेली कृती",
    "modal.indicators_title": "⚠️ आढळलेले धोक्याचे निर्देशांक",
    "modal.why_suspicious_title": "हे संशयास्पद का आहे?",
    "modal.attacker_goals_title": "हल्लेखोराला काय हवे असू शकते?",
    "modal.actions_do_title": "तुम्ही काय करावे?",
    "modal.actions_avoid_title": "हे मुळीच करू नका",
    "modal.verification_title": "पडताळणी कशी करावी",
    "modal.no_indicators": "✅ कोणताही गंभीर धोका निर्देशांक आढळला नाही",
    "modal.telemetry_title": "तांत्रिक टेलीमेट्री आणि रॉ मॉडेल JSON",
    "modal.footer_hint": "बंद करण्यासाठी ESC दाबा किंवा बाहेर क्लिक करा",
    "modal.btn_close": "अहवाल बंद करा",
    "modal.transcript_audio": "🎙️ ऑडिओ ट्रान्सक्रिप्ट",
    "modal.transcript_ocr": "📝 काढलेला मजकूर (OCR)",
    "modal.transcript_video": "🎬 व्हिडिओ फॉरेंसिक टेलीमेट्री",
    "modal.transcript_url": "🌐 यूआरएल आणि भौगोलिक स्थान माहिती",
    "modal.transcript_email": "📧 ईमेल फॉरेन्सिक डॉसियर आणि हेडर इंटेलिजन्स",
    "modal.transcript_call": "📞 कॉल थ्रेट टेलीमेट्री आणि वर्तणूक संकेत",
    "modal.score_title_email": "ईमेल फिशिंग धोका स्कोअर",
    "modal.score_title_call": "व्हॉइस कॉल स्कॅम धोका स्कोअर",
    "modal.btn_copilot": "कॉपायलटमध्ये तपासा",

    // Copilot
    "copilot.fab_title": "AI कॉपायलट",
    "copilot.fab_badge": "RAG सक्रिय",
    "copilot.title": "AI फ्रॉड इन्व्हेस्टिगेशन कॉपायलट",
    "copilot.subtitle": "RAG थ्रेट इंटेलिजेंस आणि मल्टीमॉडल सायबर तपास सहाय्यक",
    "copilot.badge_active": "सक्रिय पुरावा डॉसियर:",
    "copilot.badge_general": "मोड: सर्वसाधारण सायबर गुन्हे ज्ञानकोश",
    "copilot.btn_clear_evidence": "✕ पुरावा काढा",
    "copilot.upload_heading": "कॉपायलटमध्ये पुरावा जोडा",
    "copilot.upload_type_text": "💬 मजकूर / SMS",
    "copilot.upload_type_url": "🔗 यूआरएल लिंक",
    "copilot.upload_type_file": "📁 फाइल (मीडिया)",
    "copilot.upload_text_placeholder": "संशयास्पद मेसेज, ईमेल किंवा चॅट येथे पेस्ट करा...",
    "copilot.upload_url_placeholder": "संशयास्पद लिंक किंवा वेबसाइट प्रविष्ट करा...",
    "copilot.upload_file_drop": "स्क्रीनशॉट, ऑडिओ रेकॉर्डिंग किंवा व्हिडिओ येथे टाका",
    "copilot.upload_btn_submit": "विश्लेषण करा आणि कॉपायलटला जोडा",
    "copilot.chips_heading": "त्वरित तपास प्रश्न:",
    "copilot.chip_why": "हे संशयास्पद का आहे?",
    "copilot.chip_type": "हा कोणत्या प्रकारचा स्कॅम आहे?",
    "copilot.chip_redflags": "धोक्याचे प्रमुख संकेत कोणते?",
    "copilot.chip_goal": "हल्लेखोर काय चोरी करण्याचा प्रयत्न करत आहे?",
    "copilot.chip_action": "मी त्वरित कोणती खबरदारी घ्यावी?",
    "copilot.chip_report": "या सायबर फसवणुकीची तक्रार कशी करावी?",
    "copilot.chat_welcome": "नमस्कार! मी तुमचा **सत्य AI फ्रॉड इन्व्हेस्टिगेशन कॉपायलट** आहे. तुम्ही मला कोणत्याही पुराव्याबद्दल (मेसेज, यूआरएल, स्क्रीनशॉट, ऑडिओ, किंवा व्हिडिओ) प्रश्न विचारू शकता, किंवा सायबर गुन्हे, यूपीआय फसवणूक आणि डिजिटल सुरक्षेबद्दल चौकशी करू शकता.",
    "copilot.input_placeholder": "या धोक्याबद्दल किंवा सायबर फसवणुकीबद्दल काहीही विचारा...",
    "copilot.btn_send": "पाठवा",
    "copilot.thinking": "थ्रेट डेटाबेसची पडताळणी आणि विश्लेषण सुरू आहे...",
    "copilot.sources_title": "संदर्भ स्रोत आणि थ्रेट इंटेलिजेंस:",

    // Risk Levels
    "risk.low": "कमी (LOW)",
    "risk.medium": "मध्यम (MEDIUM)",
    "risk.high": "जास्त (HIGH)",
    "risk.critical": "अतिधोकादायक (CRITICAL)",

    // History & Footer
    "history.title": "विश्लेषण इतिहास",
    "history.empty": "या सत्रात अद्याप कोणतेही विश्लेषण केलेले नाही.",
    "footer.rights": "सत्य AI 3.0 © 2026 — मल्टीमॉडल सायबर इंटेलिजन्स प्लॅटफॉर्म",
    "footer.note": "शैक्षणिक आणि हॅकाथॉन सादरीकरणाच्या उद्देशाने.",
  }
};

let currentLanguage = localStorage.getItem("satya_lang") || "en";
if (!["en", "hi", "mr"].includes(currentLanguage)) {
  currentLanguage = "en";
}

function getLanguage() {
  return currentLanguage;
}

function t(key, fallback = "") {
  const dict = translations[currentLanguage] || translations.en;
  return dict[key] || translations.en[key] || fallback || key;
}

function applyTranslations() {
  // Update document language tag
  document.documentElement.lang = currentLanguage;

  // Text content translation via data-i18n
  document.querySelectorAll("[data-i18n]").forEach(el => {
    const key = el.getAttribute("data-i18n");
    const val = t(key);
    if (val) {
      el.textContent = val;
    }
  });

  // Placeholder translation via data-i18n-placeholder
  document.querySelectorAll("[data-i18n-placeholder]").forEach(el => {
    const key = el.getAttribute("data-i18n-placeholder");
    const val = t(key);
    if (val) {
      el.setAttribute("placeholder", val);
    }
  });

  // Title translation via data-i18n-title
  document.querySelectorAll("[data-i18n-title]").forEach(el => {
    const key = el.getAttribute("data-i18n-title");
    const val = t(key);
    if (val) {
      el.setAttribute("title", val);
    }
  });

  // Update theme text based on current theme and language
  const themeText = document.getElementById("theme-text");
  if (themeText) {
    const isLight = document.documentElement.getAttribute("data-theme") === "light";
    themeText.textContent = isLight ? t("header.theme_light") : t("header.theme_dark");
  }

  // Update language selector UI if rendered
  const selectEl = document.getElementById("lang-select");
  if (selectEl && selectEl.value !== currentLanguage) {
    selectEl.value = currentLanguage;
  }

  // Dispatch custom event for dynamic components (like scanner or dossiers)
  window.dispatchEvent(new CustomEvent("languageChanged", { detail: { lang: currentLanguage } }));
}

function setLanguage(lang) {
  if (!translations[lang]) return;
  currentLanguage = lang;
  localStorage.setItem("satya_lang", lang);
  applyTranslations();
}

// Auto-initialize once DOM is ready
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", applyTranslations);
} else {
  applyTranslations();
}
