/**
 * SATYA AI 3.0 — Modern Cybersecurity SOC Dashboard Application Logic
 * Fullscreen cyber popup modal, live scanner HUD, dark/light theme switching,
 * SPA View Router, dynamic KPI statistics, Canvas threat activity & donut charts,
 * Leaflet threat map, and dual-mode AI Fraud Investigation Copilot.
 */

// Dynamically determine backend base URL:
const API_BASE = window.location.protocol.startsWith("http") ? "" : "http://127.0.0.1:8000";
const history = [];
let currentAnalysisData = null;
let scanInterval = null;
let threatMap = null;
let threatMapMarkers = [];
let threatMapPolylines = [];

// ── Theme Management (Dark & Light) ──────────────────────────

function initTheme() {
  const savedTheme = localStorage.getItem("satyaai_theme");
  const prefersDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
  const initialTheme = savedTheme || (prefersDark ? "dark" : "light");
  setTheme(initialTheme);
}

function setTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);
  localStorage.setItem("satyaai_theme", theme);
  const text = document.getElementById("theme-text");
  if (text) {
    text.textContent = (typeof t === "function")
      ? (theme === "light" ? t("header.theme_light") : t("header.theme_dark"))
      : (theme === "light" ? "Light" : "Dark");
  }
  // Re-render canvas charts for theme contrast
  setTimeout(() => {
    drawActivityChart();
    drawDonutChart();
  }, 100);
}

document.getElementById("theme-toggle")?.addEventListener("click", () => {
  const current = document.documentElement.getAttribute("data-theme") || "dark";
  const next = current === "dark" ? "light" : "dark";
  setTheme(next);
});

// Initialize theme immediately
initTheme();

// ── Multi-Language (i18n) & Localized Samples ───────────────────────────────

const SAMPLES_DATA = {
  en: {
    msg_scam: "URGENT: Your HDFC Bank account has been temporarily suspended due to suspicious activity. Please verify your KYC immediately within 24 hours by clicking: http://bit.ly/hdfc-kyc-verify — Share your OTP to restore access.",
    msg_safe: "Hi! Just checking if you're free this weekend for the team lunch. Let me know!",
    url_phish: "http://192.168.1.105/banking-secure/login?session=verify-kyc&redirect=paypal",
    url_safe: "https://www.google.com",
    email_phish: {
      subject: "URGENT: Account Access Suspended - Immediate Action Required",
      sender: "security-alert@sbi-online-service.com",
      body: "Dear Valued Customer,\n\nWe detected suspicious attempts to access your bank account. Your account has been temporarily restricted.\n\nTo restore full services immediately, verify your credentials at our secure portal: http://192.168.1.55/auth/verify?session=9283\n\nFailure to verify within 24 hours will lead to permanent account deactivation.\n\nRegards,\nBank Fraud Prevention Team"
    },
    email_safe: {
      subject: "Sprint Review & Platform Architecture Sync",
      sender: "alex.kumar@organization.org",
      body: "Hi team,\n\nHere is the reminder for our weekly architecture review this Thursday at 3:00 PM IST. Please review the updated design documents beforehand.\n\nBest regards,\nEngineering Team"
    },
    call_scam: "Hello, I am Inspector Rajesh Sharma calling from Mumbai Cyber Crime Branch. An FIR has been registered against your Aadhaar card for money laundering. An arrest warrant will be issued in 30 minutes. To cancel the warrant, you must immediately transfer your funds to our RBI secret safe verification account. Please read your OTP.",
    call_safe: "Good afternoon, this is Priya calling from Tech Support regarding ticket 4092. We noticed your issue has been resolved. Please confirm if everything is working normally on your end."
  },
  hi: {
    msg_scam: "अति आवश्यक: संदिग्ध गतिविधि के कारण आपका HDFC बैंक खाता अस्थायी रूप से निलंबित कर दिया गया है। 24 घंटे के भीतर KYC सत्यापित करें: http://bit.ly/hdfc-kyc-verify — पहुंच बहाल करने के लिए अपना OTP साझा करें।",
    msg_safe: "नमस्ते! बस यह जानने के लिए मैसेज किया कि क्या आप इस सप्ताहांत टीम लंच के लिए फ्री हैं? मुझे बताएं!",
    url_phish: "http://192.168.1.105/banking-secure/login?session=verify-kyc&redirect=paypal",
    url_safe: "https://www.google.com",
    email_phish: {
      subject: "अति आवश्यक: खाता पहुंच निलंबित - तत्काल कार्रवाई आवश्यक",
      sender: "security-alert@sbi-online-service.com",
      body: "प्रिय ग्राहक,\n\nहमने आपके बैंक खाते में संदिग्ध लॉगिन प्रयास देखे हैं। आपका खाता अस्थायी रूप से प्रतिबंधित कर दिया गया है।\n\nतुरंत सेवाएं बहाल करने के लिए अपने विवरण सत्यापित करें: http://192.168.1.55/auth/verify?session=9283\n\n24 घंटे के भीतर सत्यापन न करने पर खाता स्थायी रूप से निष्क्रिय हो जाएगा।\n\nधन्यवाद,\nबैंक धोखाधड़ी निवारण टीम"
    },
    email_safe: {
      subject: "स्प्रिंट समीक्षा और प्लेटफ़ॉर्म आर्किटेक्चर बैठक",
      sender: "alex.kumar@organization.org",
      body: "नमस्ते टीम,\n\nइस गुरुवार दोपहर 3:00 बजे हमारी साप्ताहिक समीक्षा बैठक है। कृपया पहले से दस्तावेज़ देख लें।\n\nसादर,\nइंजीनियरिंग टीम"
    },
    call_scam: "नमस्ते, मैं मुंबई साइबर क्राइम ब्रांच से इंस्पेक्टर राजेश शर्मा बोल रहा हूं। आपके आधार कार्ड पर मनी लॉन्ड्रिंग की एफआईआर दर्ज हुई है। 30 मिनट में गिरफ्तारी वारंट जारी होगा। वारंट रद्द कराने के लिए तुरंत आरबीआई सत्यापन खाते में पैसे ट्रांसफर करें और ओटीपी बताएं।",
    call_safe: "नमस्कार, मैं टेक सपोर्ट से प्रिया बात कर रही हूं टिकट 4092 के संबंध में। क्या आपकी समस्या हल हो गई है? कृपया पुष्टि करें।"
  },
  mr: {
    msg_scam: "तातडीचे: संशयास्पद हालचालींमुळे तुमचे HDFC बँक खाते तात्पुरते निलंबित करण्यात आले आहे. 24 तासांच्या आत KYC पडताळणी करा: http://bit.ly/hdfc-kyc-verify — प्रवेश पुनर्संचयित करण्यासाठी OTP शेअर करा.",
    msg_safe: "नमस्कार! या वीकेंडला टीम लंचसाठी वेळ आहे का ते विचारण्यासाठी मेसेज केला. कळवा!",
    url_phish: "http://192.168.1.105/banking-secure/login?session=verify-kyc&redirect=paypal",
    url_safe: "https://www.google.com",
    email_phish: {
      subject: "तातडीचे: खात्याचा प्रवेश निलंबित - त्वरित कृती आवश्यक",
      sender: "security-alert@sbi-online-service.com",
      body: "प्रिय ग्राहक,\n\nतुमच्या बँक खात्यात संशयास्पद हालचाली आढळल्या आहेत. सेवा तात्पुरती बंद करण्यात आली आहे.\n\nपुनर्संचयित करण्यासाठी येथे पडताळणी करा: http://192.168.1.55/auth/verify?session=9283\n\n24 तासांत पडताळणी न केल्यास खाते कायमचे बंद होईल.\n\nबँक सुरक्षा पथक"
    },
    email_safe: {
      subject: "स्प्रिंट पुनरावलोकन व प्लॅटफॉर्म आर्किटेक्चर बैठक",
      sender: "alex.kumar@organization.org",
      body: "नमस्कार टीम,\n\nया गुरुवारी दुपारी 3:00 वाजता आमची साप्ताहिक बैठक आहे. कृपया आधी अपडेटेड डिझाइन तपासा.\n\nइंजिनिअरिंग टीम"
    },
    call_scam: "नमस्कार, मी मुंबई सायबर गुन्हे शाखेतून इन्स्पेक्टर बोलत आहे. तुमच्या आधार कार्डवर एफआयआर नोंदवला गेला आहे. 30 मिनिटांत अटक वॉरंट निघेल. ते रद्द करण्यासाठी त्वरित पैसे ट्रान्सफर करा आणि ओटीपी सांगा.",
    call_safe: "नमस्कार, मी टेक सपोर्टमधून प्रिया बोलत आहे तिकीट 4092 संदर्भात. आपली समस्या सुटली आहे का कृपया सांगा."
  }
};

function getLocalizedSamples() {
  const currentLang = (typeof getCurrentLang === "function") ? getCurrentLang() : "en";
  return SAMPLES_DATA[currentLang] || SAMPLES_DATA.en;
}

// ── SPA View Router (11 Operational Views) ───────────────────────────────────

function switchView(viewName) {
  if (!viewName) viewName = "dashboard";
  const views = document.querySelectorAll(".app-view");
  const navItems = document.querySelectorAll(".sidebar-nav .nav-item");

  views.forEach(v => v.classList.remove("active"));
  navItems.forEach(n => n.classList.remove("active"));

  const targetView = document.getElementById(`view-${viewName}`);
  const targetNav = document.getElementById(`btn-nav-${viewName}`);

  if (targetView) {
    targetView.classList.add("active");
  } else {
    document.getElementById("view-dashboard")?.classList.add("active");
  }

  if (targetNav) {
    targetNav.classList.add("active");
  }

  // Synchronize URL hash
  if (window.location.hash !== `#${viewName}`) {
    window.history.replaceState(null, null, `#${viewName}`);
  }

  // Close mobile drawer if open
  closeMobileDrawer();

  // View-specific initializations
  if (viewName === "dashboard") {
    setTimeout(updateDashboardTelemetry, 50);
  } else if (viewName === "geo") {
    setTimeout(initOrRefreshThreatMap, 150);
  } else if (viewName === "reports") {
    renderReportsArchive();
  } else if (viewName === "settings") {
    refreshModelHealth();
  } else if (viewName === "copilot") {
    setTimeout(() => {
      document.getElementById("v2-copilot-input")?.focus();
    }, 100);
  }
}

// Sidebar collapse & mobile drawer logic
function initSidebarControls() {
  const sidebar = document.getElementById("app-sidebar");
  const collapseBtn = document.getElementById("btn-collapse-sidebar");
  const drawerBtn = document.getElementById("btn-mobile-drawer");
  const backdrop = document.getElementById("sidebar-backdrop");

  collapseBtn?.addEventListener("click", () => {
    sidebar?.classList.toggle("collapsed");
    setTimeout(() => {
      drawActivityChart();
      drawDonutChart();
      if (threatMap) threatMap.invalidateSize();
    }, 260);
  });

  drawerBtn?.addEventListener("click", () => {
    sidebar?.classList.add("drawer-open");
    backdrop?.classList.add("active");
  });

  backdrop?.addEventListener("click", closeMobileDrawer);

  // Wire sidebar navigation items
  document.querySelectorAll(".sidebar-nav .nav-item").forEach(btn => {
    btn.addEventListener("click", () => {
      const view = btn.dataset.view;
      if (view) switchView(view);
    });
  });

  // Handle URL hash routing on initial load and hashchange
  window.addEventListener("hashchange", () => {
    const hash = window.location.hash.replace("#", "");
    if (hash) switchView(hash);
  });

  const initialHash = window.location.hash.replace("#", "");
  switchView(initialHash || "dashboard");
}

function closeMobileDrawer() {
  document.getElementById("app-sidebar")?.classList.remove("drawer-open");
  document.getElementById("sidebar-backdrop")?.classList.remove("active");
}

// Quick Actions in Dashboard & Time Range Filters
let currentChartRange = "7d";

function initQuickActions() {
  document.querySelectorAll(".qa-btn, .qa-row-item").forEach(btn => {
    btn.addEventListener("click", () => {
      const targetView = btn.dataset.targetView;
      const targetTab = btn.dataset.targetTab;
      if (targetView) {
        switchView(targetView);
        if (targetTab && typeof switchTab === "function") {
          switchTab(targetTab);
        }
      }
    });
  });

  document.getElementById("btn-view-all-reports")?.addEventListener("click", () => {
    switchView("reports");
  });
  document.getElementById("btn-analysis-view-all")?.addEventListener("click", () => {
    switchView("reports");
  });
  document.getElementById("btn-threats-view-all")?.addEventListener("click", () => {
    switchView("detection");
  });

  // Chart time pills (7D, 30D, 90D)
  document.querySelectorAll(".chart-time-pills .time-pill").forEach(pill => {
    pill.addEventListener("click", () => {
      document.querySelectorAll(".chart-time-pills .time-pill").forEach(p => p.classList.remove("active"));
      pill.classList.add("active");
      currentChartRange = pill.dataset.range || "7d";
      drawActivityChart();
    });
  });
}

// ── Persistent History & Dashboard Telemetry ────────────────────────────────

const BASELINE_THREATS = [
  {
    modality: "email",
    preview: "user123@gmail.com",
    score: 92,
    level: "HIGH",
    timeStr: "Today, 10:24 AM",
    threatTitle: "Phishing Email",
    threatTarget: "suspicious-link@betr.com",
    threatAge: "2h ago",
    badge: "high",
    badgeText: "High",
    iconType: "red",
    time: new Date(Date.now() - 2 * 3600 * 1000),
  },
  {
    modality: "url",
    preview: "http://malicious-site.com",
    score: 85,
    level: "HIGH",
    timeStr: "Today, 09:12 AM",
    threatTitle: "Malicious URL",
    threatTarget: "http://fake-login-secure.com",
    threatAge: "4h ago",
    badge: "medium",
    badgeText: "Medium",
    iconType: "orange",
    time: new Date(Date.now() - 4 * 3600 * 1000),
  },
  {
    modality: "image",
    preview: "photo.jpg",
    score: 12,
    level: "LOW",
    timeStr: "Today, 08:47 AM",
    threatTitle: "Suspicious Image",
    threatTarget: "IMG_4821.jpg",
    threatAge: "6h ago",
    badge: "medium",
    badgeText: "Medium",
    iconType: "purple",
    time: new Date(Date.now() - 6 * 3600 * 1000),
  },
  {
    modality: "call",
    preview: "+91 91234 56789",
    score: 48,
    level: "MEDIUM",
    timeStr: "Today, 07:33 AM",
    threatTitle: "Fraud Call",
    threatTarget: "+91 98765 43210",
    threatAge: "8h ago",
    badge: "low",
    badgeText: "Low",
    iconType: "green",
    time: new Date(Date.now() - 8 * 3600 * 1000),
  },
  {
    modality: "video",
    preview: "video.mp4",
    score: 10,
    level: "LOW",
    timeStr: "Today, 06:21 AM",
    threatTitle: "Phishing Email",
    threatTarget: "bank-alert@update.com",
    threatAge: "10h ago",
    badge: "high",
    badgeText: "High",
    iconType: "red",
    time: new Date(Date.now() - 10 * 3600 * 1000),
  }
];

function loadStoredHistory() {
  try {
    const raw = localStorage.getItem("satya_analysis_history");
    if (raw) {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed) && parsed.length > 0) {
        parsed.forEach(p => {
          history.push({
            ...p,
            time: new Date(p.time || Date.now()),
          });
        });
        return;
      }
    }
  } catch (err) {
    console.warn("Could not load stored history:", err);
  }

  // If no previous history, initialize with realistic baseline records matching the UI
  BASELINE_THREATS.forEach(item => history.push({ ...item }));
}

function saveHistoryToStorage() {
  try {
    localStorage.setItem("satya_analysis_history", JSON.stringify(history.slice(0, 30)));
  } catch (err) {
    console.warn("Could not save history to storage:", err);
  }
}

const TAB_ICONS = {
  message: "💬",
  url: "🔗",
  email: "✉️",
  call: "📞",
  image: "🖼️",
  video: "🎬",
  audio: "🎙️",
};

function addHistory(modality, preview, score, level, data) {
  const now = new Date();
  const timeStr = `Today, ${now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`;
  const numScore = Math.round(score || 0);
  const upperLevel = (level || "LOW").toUpperCase();

  let badge = "low";
  let badgeText = "Low";
  let iconType = "green";
  if (upperLevel === "HIGH" || upperLevel === "CRITICAL" || numScore > 65) {
    badge = "high";
    badgeText = "High";
    iconType = "red";
  } else if (upperLevel === "MEDIUM" || numScore > 35) {
    badge = "medium";
    badgeText = "Medium";
    iconType = "orange";
  }

  const threatTitle = modality === "email" ? "Phishing Email"
    : modality === "url" ? "Malicious URL"
    : modality === "call" ? "Fraud Call"
    : modality === "image" ? "Suspicious Image"
    : modality === "video" ? "Video Deepfake"
    : "Scam Message";

  const item = {
    modality,
    preview,
    score: numScore,
    level: upperLevel,
    timeStr,
    threatTitle,
    threatTarget: preview || "Target Vector",
    threatAge: "Just now",
    badge,
    badgeText,
    iconType,
    data,
    time: now,
  };

  history.unshift(item);
  if (history.length > 50) history.pop();

  saveHistoryToStorage();
  updateDashboardTelemetry();
  if (typeof updateGeoMapMarkers === "function") updateGeoMapMarkers();

  // Toast notification
  if (window.SatyaComponents && window.SatyaComponents.showToast) {
    window.SatyaComponents.showToast(
      `Analyzed ${modality.toUpperCase()}: Risk ${item.score}/100 [${item.level}]`,
      item.level === "LOW" || item.level === "SAFE" ? "success" : (item.level === "MEDIUM" ? "warning" : "error")
    );
  }
}

function updateDashboardTelemetry() {
  // Base counts matching the reference UI + live additions
  const sessionNewTotal = history.filter(h => !h.threatAge || h.threatAge === "Just now").length;
  const sessionNewEmail = history.filter(h => h.modality === "email" && h.threatAge === "Just now").length;
  const sessionNewCall = history.filter(h => (h.modality === "call" || h.modality === "audio") && h.threatAge === "Just now").length;
  const sessionNewUrl = history.filter(h => h.modality === "url" && h.threatAge === "Just now").length;

  const totalCount = 24 + sessionNewTotal;
  const emailCount = 8 + sessionNewEmail;
  const callCount = 3 + sessionNewCall;
  const urlCount = 7 + sessionNewUrl;

  const totalThreatsEl = document.getElementById("kpi-total-threats");
  const emailThreatsEl = document.getElementById("kpi-email-threats");
  const callThreatsEl = document.getElementById("kpi-call-threats");
  const urlThreatsEl = document.getElementById("kpi-url-threats");

  if (totalThreatsEl) totalThreatsEl.textContent = totalCount;
  if (emailThreatsEl) emailThreatsEl.textContent = emailCount;
  if (callThreatsEl) callThreatsEl.textContent = callCount;
  if (urlThreatsEl) urlThreatsEl.textContent = urlCount;

  // 2. System Risk Score Gauge (Default: 18% Low Risk matching image)
  let riskScore = 18;
  if (sessionNewTotal > 0) {
    const sum = history.reduce((acc, h) => acc + (h.score || 0), 0);
    riskScore = Math.round(sum / history.length);
  }

  const riskValEl = document.getElementById("kpi-risk-val");
  const riskCircleEl = document.getElementById("kpi-risk-circle");
  const riskLabelEl = document.getElementById("kpi-risk-label");
  const riskDescEl = document.getElementById("kpi-risk-desc");

  if (riskValEl) riskValEl.textContent = `${riskScore}%`;
  if (riskCircleEl) {
    riskCircleEl.setAttribute("stroke-dasharray", `${riskScore}, 100`);
    if (riskScore <= 30) {
      riskCircleEl.style.stroke = "#10b981";
      if (riskLabelEl) { riskLabelEl.style.color = "#16a34a"; riskLabelEl.textContent = "Low Risk"; }
      if (riskDescEl) riskDescEl.textContent = "Great! Your system is safe for now.";
    } else if (riskScore <= 60) {
      riskCircleEl.style.stroke = "#f59e0b";
      if (riskLabelEl) { riskLabelEl.style.color = "#d97706"; riskLabelEl.textContent = "Moderate Risk"; }
      if (riskDescEl) riskDescEl.textContent = "Caution: Medium threat level detected.";
    } else {
      riskCircleEl.style.stroke = "#ef4444";
      if (riskLabelEl) { riskLabelEl.style.color = "#dc2626"; riskLabelEl.textContent = "High Risk"; }
      if (riskDescEl) riskDescEl.textContent = "Warning: Active threats require immediate mitigation.";
    }
  }

  // 3. Render Canvas Charts
  drawActivityChart();
  drawDonutChart();

  // 4. Render Recent Threats Feed
  renderRecentThreatsFeed();
  syncQuickActionsHeight();

  // 5. Render Recent Analysis Table
  renderRecentAnalysisTable();

  // 6. Update Geo Map markers
  if (typeof updateGeoMapMarkers === "function") {
    updateGeoMapMarkers();
  }
}

// ── HTML5 Canvas Charts (Activity Overview & Donut Distribution) ─────────────

function drawActivityChart() {
  const canvas = document.getElementById("threat-activity-chart");
  if (!canvas) return;

  const ctx = canvas.getContext("2d");
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  const width = rect.width || 560;
  const height = rect.height || 210;

  canvas.width = width * dpr;
  canvas.height = height * dpr;
  ctx.scale(dpr, dpr);

  ctx.clearRect(0, 0, width, height);

  // Time range data points
  let labels = ["Sep 6", "Sep 7", "Sep 8", "Sep 9", "Sep 10", "Sep 11", "Sep 12"];
  let values = [14, 13, 25, 18, 17, 13, 16];

  if (currentChartRange === "30d") {
    labels = ["Aug 15", "Aug 20", "Aug 25", "Aug 30", "Sep 4", "Sep 8", "Sep 12"];
    values = [18, 22, 16, 29, 21, 26, 16];
  } else if (currentChartRange === "90d") {
    labels = ["Jun", "Jul W1", "Jul W3", "Aug W1", "Aug W3", "Sep W1", "Sep W2"];
    values = [24, 31, 20, 35, 28, 22, 16];
  }

  const padding = { top: 25, right: 25, bottom: 35, left: 45 };
  const chartW = width - padding.left - padding.right;
  const chartH = height - padding.top - padding.bottom;
  const maxY = 40;

  // Grid lines and Y-axis labels (0, 10, 20, 30, 40)
  ctx.strokeStyle = "#f1f5f9";
  ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i++) {
    const val = i * 10;
    const y = padding.top + chartH - (chartH * (val / maxY));
    ctx.beginPath();
    ctx.moveTo(padding.left, y);
    ctx.lineTo(padding.left + chartW, y);
    ctx.stroke();

    ctx.fillStyle = "#94a3b8";
    ctx.font = "11px Inter, sans-serif";
    ctx.textAlign = "right";
    ctx.fillText(`${val}`, padding.left - 8, y + 4);
  }

  // X-axis labels
  const stepX = chartW / (labels.length - 1);
  ctx.textAlign = "center";
  labels.forEach((label, i) => {
    const x = padding.left + i * stepX;
    ctx.fillText(label, x, height - 10);
  });

  // Calculate coordinates for points
  const points = values.map((val, i) => ({
    x: padding.left + i * stepX,
    y: padding.top + chartH - (chartH * (val / maxY)),
    val,
  }));

  // Gradient area fill under spline curve
  const grad = ctx.createLinearGradient(0, padding.top, 0, padding.top + chartH);
  grad.addColorStop(0, "rgba(22, 136, 255, 0.22)");
  grad.addColorStop(0.7, "rgba(22, 136, 255, 0.08)");
  grad.addColorStop(1, "rgba(22, 136, 255, 0.0)");

  ctx.beginPath();
  ctx.moveTo(points[0].x, points[0].y);
  for (let i = 0; i < points.length - 1; i++) {
    const xc = (points[i].x + points[i + 1].x) / 2;
    const yc = (points[i].y + points[i + 1].y) / 2;
    ctx.quadraticCurveTo(points[i].x, points[i].y, xc, yc);
  }
  ctx.lineTo(points[points.length - 1].x, points[points.length - 1].y);
  ctx.lineTo(points[points.length - 1].x, padding.top + chartH);
  ctx.lineTo(points[0].x, padding.top + chartH);
  ctx.closePath();
  ctx.fillStyle = grad;
  ctx.fill();

  // Smooth curved line
  ctx.beginPath();
  ctx.moveTo(points[0].x, points[0].y);
  for (let i = 0; i < points.length - 1; i++) {
    const xc = (points[i].x + points[i + 1].x) / 2;
    const yc = (points[i].y + points[i + 1].y) / 2;
    ctx.quadraticCurveTo(points[i].x, points[i].y, xc, yc);
  }
  ctx.lineTo(points[points.length - 1].x, points[points.length - 1].y);
  ctx.strokeStyle = "#1688ff";
  ctx.lineWidth = 2.5;
  ctx.stroke();

  // Draw circular dots on data points
  points.forEach(p => {
    ctx.beginPath();
    ctx.arc(p.x, p.y, 4, 0, Math.PI * 2);
    ctx.fillStyle = "#1688ff";
    ctx.fill();
    ctx.lineWidth = 2;
    ctx.strokeStyle = "#ffffff";
    ctx.stroke();
  });
}

function drawDonutChart() {
  const canvas = document.getElementById("threat-donut-chart");
  const totalEl = document.getElementById("donut-center-total");
  if (!canvas) return;

  const ctx = canvas.getContext("2d");
  const dpr = window.devicePixelRatio || 1;
  const size = 220;
  canvas.width = size * dpr;
  canvas.height = size * dpr;
  ctx.scale(dpr, dpr);

  ctx.clearRect(0, 0, size, size);

  if (totalEl) totalEl.textContent = "24";

  // Exact distribution from the reference UI
  const segments = [
    { count: 8, color: "#1688ff" }, // Phishing Email (33%)
    { count: 7, color: "#ef4444" }, // Malicious URL (29%)
    { count: 4, color: "#a855f7" }, // Image/Video (17%)
    { count: 3, color: "#10b981" }, // Fraud Call (12%)
    { count: 2, color: "#94a3b8" }, // Others (8%)
  ];
  const total = 24;

  const center = size / 2;
  const radius = 78;
  const thickness = 20;

  let startAngle = -Math.PI / 2;
  segments.forEach(seg => {
    const sliceAngle = (seg.count / total) * Math.PI * 2;
    ctx.beginPath();
    ctx.arc(center, center, radius, startAngle, startAngle + sliceAngle - 0.04);
    ctx.strokeStyle = seg.color;
    ctx.lineWidth = thickness;
    ctx.lineCap = "round";
    ctx.stroke();
    startAngle += sliceAngle;
  });
}

function syncQuickActionsHeight() {
  const feed = document.querySelector(".recent-threats-panel");
  const qa = document.querySelector(".quick-actions-panel");
  if (!feed || !qa) return;
  if (window.innerWidth >= 1200) {
    const feedH = feed.offsetHeight;
    if (feedH > 0) {
      qa.style.height = `${feedH}px`;
    }
  } else {
    qa.style.height = "";
  }
}
window.addEventListener("resize", syncQuickActionsHeight);

// ── Feed and Data Table Renderers ────────────────────────────────────────────

function renderRecentThreatsFeed() {
  const container = document.getElementById("dash-recent-threats-list");
  if (!container) return;

  container.innerHTML = "";

  const threats = history.slice(0, 5);

  threats.forEach(t => {
    const row = document.createElement("div");
    row.className = "clean-threat-row";

    // SVG Icons matching modality
    let svgIcon = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>`;
    let colorClass = t.iconType || "red";

    if (t.modality === "url") {
      svgIcon = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>`;
      colorClass = "orange";
    } else if (t.modality === "image" || t.modality === "media") {
      svgIcon = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg>`;
      colorClass = "purple";
    } else if (t.modality === "call") {
      svgIcon = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72 12.84 12.84 0 0 0 .7 2.81 2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7A2 2 0 0 1 22 16.92z"/></svg>`;
      colorClass = "green";
    }

    row.innerHTML = `
      <div class="clean-threat-left">
        <div class="clean-threat-icon-circle ${colorClass}">
          ${svgIcon}
        </div>
        <div class="clean-threat-texts">
          <span class="clean-threat-name">${escapeHTML(t.threatTitle || "Phishing Threat")}</span>
          <span class="clean-threat-sub">${escapeHTML(t.threatTarget || t.preview || "—")}</span>
        </div>
      </div>
      <div class="clean-threat-right">
        <span class="clean-threat-time">${t.threatAge || "2h ago"}</span>
        <span class="clean-pill-badge ${t.badge || 'medium'}">${t.badgeText || 'Medium'}</span>
      </div>
    `;

    row.addEventListener("click", () => {
      if (t.data && typeof renderResults === "function") {
        renderResults(t.data, t.modality, t.preview);
      } else {
        switchView("detection");
      }
    });

    container.appendChild(row);
  });

  // Keep Quick Threat Actions length equal to Recent Threats Feed
  requestAnimationFrame(syncQuickActionsHeight);
}

function renderRecentAnalysisTable() {
  const tbody = document.getElementById("dash-analysis-tbody");
  if (!tbody) return;

  tbody.innerHTML = "";

  const rows = history.slice(0, 5);

  rows.forEach(r => {
    const tr = document.createElement("tr");

    let typeLabel = "Email";
    let dotClass = "email";
    let resBadge = "high";
    let resText = "Malicious";

    if (r.modality === "email") {
      typeLabel = "Email";
      dotClass = "email";
      resBadge = "high";
      resText = "Malicious";
    } else if (r.modality === "url") {
      typeLabel = "URL";
      dotClass = "url";
      resBadge = "high";
      resText = "Malicious";
    } else if (r.modality === "image") {
      typeLabel = "Image";
      dotClass = "image";
      resBadge = "low";
      resText = "Clean";
    } else if (r.modality === "call") {
      typeLabel = "Call";
      dotClass = "call";
      resBadge = "medium";
      resText = "Suspicious";
    } else if (r.modality === "video") {
      typeLabel = "Video";
      dotClass = "video";
      resBadge = "low";
      resText = "Clean";
    } else {
      typeLabel = r.modality.toUpperCase();
      dotClass = "email";
      resBadge = r.level === "LOW" ? "low" : (r.level === "MEDIUM" ? "medium" : "high");
      resText = r.level === "LOW" ? "Clean" : (r.level === "MEDIUM" ? "Suspicious" : "Malicious");
    }

    tr.innerHTML = `
      <td>
        <span class="table-type-cell">
          <span class="table-type-dot ${dotClass}"></span>
          ${typeLabel}
        </span>
      </td>
      <td>
        <span class="table-source-text" title="${escapeHTML(r.preview || '')}">${escapeHTML(r.preview || "—")}</span>
      </td>
      <td>
        <span class="clean-pill-badge ${resBadge}">${resText}</span>
      </td>
      <td>
        <span class="table-time-text">${r.timeStr || "Today, 10:24 AM"}</span>
      </td>
    `;

    tr.addEventListener("click", () => {
      if (r.data && typeof renderResults === "function") {
        renderResults(r.data, r.modality, r.preview);
      } else {
        switchView("reports");
      }
    });

    tbody.appendChild(tr);
  });
}

function renderReportsArchive() {
  const list = document.getElementById("reports-archive-list");
  const empty = document.getElementById("reports-empty-state");
  if (!list) return;

  if (history.length === 0) {
    if (empty) empty.hidden = false;
    return;
  }
  if (empty) empty.hidden = true;

  list.querySelectorAll(".report-archive-item").forEach(i => i.remove());

  history.forEach((item, idx) => {
    const el = document.createElement("div");
    el.className = "report-archive-item";
    el.innerHTML = `
      <div class="report-item-meta">
        <span class="report-item-title">${TAB_ICONS[item.modality] || "📄"} Threat Dossier #${history.length - idx}: ${item.modality.toUpperCase()}</span>
        <span class="report-item-sub">Analyzed at ${item.time.toLocaleString()} · Score: ${item.score}/100 [${item.level}]</span>
      </div>
      <div class="report-item-actions">
        ${renderThreatBadge(item.level)}
        <button type="button" class="report-btn btn-view-report">Open Dossier</button>
      </div>
    `;
    el.querySelector(".btn-view-report").addEventListener("click", () => {
      if (item.data) renderResults(item.data, item.modality, item.preview);
    });
    list.appendChild(el);
  });
}

document.getElementById("btn-clear-all-reports")?.addEventListener("click", () => {
  if (confirm("Clear all session threat dossiers?")) {
    history.length = 0;
    saveHistoryToStorage();
    updateDashboardTelemetry();
    renderReportsArchive();
  }
});

function renderThreatBadge(level = "LOW") {
  if (window.SatyaComponents && window.SatyaComponents.renderThreatBadge) {
    return window.SatyaComponents.renderThreatBadge(level);
  }
  const l = (level || "LOW").toUpperCase();
  let cls = "badge-low";
  if (l === "MEDIUM") cls = "badge-medium";
  else if (l === "HIGH") cls = "badge-high";
  else if (l === "CRITICAL" || l === "SCAM" || l === "PHISHING" || l === "FAKE") cls = "badge-critical";
  return `<span class="threat-badge ${cls}">${l}</span>`;
}

// ── Geolocation Threat Map Controller (Leaflet Dark) ─────────────────────────

function initOrRefreshThreatMap() {
  const container = document.getElementById("geo-map-container");
  if (!container || typeof L === "undefined") return;

  if (!threatMap) {
    threatMap = L.map("geo-map-container", {
      center: [20.5937, 78.9629], // India / Global center
      zoom: 3,
      zoomControl: true,
      attributionControl: false,
    });

    L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
      maxZoom: 18,
      subdomains: "abcd",
    }).addTo(threatMap);
  }

  threatMap.invalidateSize();
  updateGeoMapMarkers();
}

function updateGeoMapMarkers() {
  if (!threatMap || typeof L === "undefined") return;

  // Clear previous markers and polylines
  threatMapMarkers.forEach(m => {
    try { threatMap.removeLayer(m); } catch (e) {}
  });
  threatMapMarkers = [];

  threatMapPolylines.forEach(p => {
    try { threatMap.removeLayer(p); } catch (e) {}
  });
  threatMapPolylines = [];

  const geoList = document.getElementById("geo-ip-list");
  const emptyState = document.getElementById("geo-empty-state");
  const countBadge = document.getElementById("geo-endpoint-count");
  const statusPill = document.getElementById("map-status-pill");

  // Collect markers from currentAnalysisData and history
  const markerMap = new Map(); // ip or label -> marker object
  const activeHopCoords = [];

  // Helper to ingest threat_origin payload
  const ingestOrigin = (origin, isCurrent = false) => {
    if (!origin || !Array.isArray(origin.markers)) return;
    origin.markers.forEach(m => {
      if (!m || !m.ip) return;
      const key = m.ip;
      if (!markerMap.has(key)) {
        markerMap.set(key, { ...m, isCurrent });
      }
      if (isCurrent && typeof m.latitude === "number" && typeof m.longitude === "number" && !(m.latitude === 0 && m.longitude === 0)) {
        activeHopCoords.push([m.latitude, m.longitude]);
      }
    });
  };

  // 1. Current active analysis
  if (currentAnalysisData) {
    const currentOrigin = currentAnalysisData.threat_origin || currentAnalysisData.analysis?.threat_origin;
    ingestOrigin(currentOrigin, true);
  }

  // 2. History analyses
  if (Array.isArray(history)) {
    history.forEach(h => {
      const d = h.data || {};
      const origin = d.threat_origin || d.analysis?.threat_origin;
      if (origin) {
        ingestOrigin(origin, false);
      } else if (d.analysis?.domain_info?.ip && d.geolocation?.latitude && d.geolocation?.longitude) {
        // Fallback for legacy telemetry with real coords
        const ip = d.analysis.domain_info.ip;
        if (!markerMap.has(ip)) {
          markerMap.set(ip, {
            type: "domain",
            label: d.analysis.domain_info.domain || ip,
            ip: ip,
            country: d.geolocation.country || "Unknown",
            country_code: d.geolocation.country_code || "",
            region: d.geolocation.region || "",
            city: d.geolocation.city || "",
            latitude: d.geolocation.latitude,
            longitude: d.geolocation.longitude,
            isp: d.geolocation.isp || "Unknown",
            organization: d.geolocation.org || "",
            asn: d.geolocation.asn || "",
            risk_score: h.score || 0,
            threat_type: h.type || "Threat Analysis",
            source: "Network Telemetry",
            isCurrent: false,
          });
        }
      }
    });
  }

  const allItems = Array.from(markerMap.values());
  const plottableItems = allItems.filter(
    item => typeof item.latitude === "number" &&
            typeof item.longitude === "number" &&
            !isNaN(item.latitude) &&
            !isNaN(item.longitude) &&
            !(item.latitude === 0 && item.longitude === 0)
  );

  if (countBadge) {
    countBadge.textContent = `${plottableItems.length} Endpoint${plottableItems.length === 1 ? "" : "s"}`;
  }

  if (statusPill) {
    statusPill.textContent = plottableItems.length > 0 ? "Active Telemetry" : "Ready";
    statusPill.classList.toggle("loading", false);
  }

  if (plottableItems.length === 0) {
    if (emptyState) emptyState.hidden = false;
    if (geoList) {
      geoList.querySelectorAll(".geo-ip-item").forEach(el => el.remove());
    }
    return;
  }

  if (emptyState) emptyState.hidden = true;

  if (geoList) {
    geoList.querySelectorAll(".geo-ip-item").forEach(el => el.remove());
  }

  const latLngBounds = [];

  plottableItems.forEach(item => {
    // Risk score and color mapping
    const score = item.risk_score != null ? item.risk_score : 0;
    const isHigh = score >= 60 || item.risk_level === "CRITICAL" || item.risk_level === "HIGH";
    const isMed = score >= 30 && score < 60;
    const markerColor = isHigh ? "#ef4444" : (isMed ? "#f59e0b" : "#00f5ff");
    const riskBadgeClass = isHigh ? "HIGH" : (isMed ? "MEDIUM" : "LOW");

    // Location formatted string
    const locParts = [item.city, item.region, item.country].filter(Boolean);
    const locString = locParts.length > 0 ? locParts.join(", ") : "Unknown Location";

    // Marker radius: active/originating host slightly larger
    const radius = (item.isCurrent || item.type === "originating_ip" || item.type === "url_host") ? 9 : 7;

    const marker = L.circleMarker([item.latitude, item.longitude], {
      radius: radius,
      color: markerColor,
      fillColor: markerColor,
      fillOpacity: 0.8,
      weight: item.isCurrent ? 3 : 2,
    }).addTo(threatMap);

    const popupHTML = `
      <div class="threat-popup-card">
        <div class="threat-popup-header">
          <span class="threat-popup-type" style="color:${markerColor}">⚡ ${escapeHTML((item.type || 'infrastructure').replace(/_/g, ' '))}</span>
          <span class="threat-popup-badge ${riskBadgeClass}">${escapeHTML(riskBadgeClass)}</span>
        </div>
        <div class="threat-popup-row">
          <span class="threat-popup-label">Target / Host:</span>
          <span class="threat-popup-val">${escapeHTML(item.label || 'N/A')}</span>
        </div>
        <div class="threat-popup-row">
          <span class="threat-popup-label">Public IP:</span>
          <span class="threat-popup-val mono">${escapeHTML(item.ip)}</span>
        </div>
        <div class="threat-popup-row">
          <span class="threat-popup-label">Approx Location:</span>
          <span class="threat-popup-val">${escapeHTML(locString)}</span>
        </div>
        <div class="threat-popup-row">
          <span class="threat-popup-label">ISP / Org:</span>
          <span class="threat-popup-val">${escapeHTML(item.isp || item.organization || 'Unknown')}</span>
        </div>
        ${item.asn ? `
        <div class="threat-popup-row">
          <span class="threat-popup-label">ASN:</span>
          <span class="threat-popup-val mono">${escapeHTML(item.asn)}</span>
        </div>` : ''}
        <div class="threat-popup-row">
          <span class="threat-popup-label">Risk Score:</span>
          <span class="threat-popup-val" style="color:${markerColor}">${score}/100</span>
        </div>
        <div class="threat-popup-row">
          <span class="threat-popup-label">Intel Source:</span>
          <span class="threat-popup-val">${escapeHTML(item.source || 'Threat Intelligence')}</span>
        </div>
        <div class="threat-popup-disclaimer">
          ℹ️ Locations are approximate and represent analyzed network infrastructure, not necessarily the attacker's physical location.
        </div>
      </div>
    `;

    marker.bindPopup(popupHTML);
    threatMapMarkers.push(marker);
    latLngBounds.push([item.latitude, item.longitude]);

    // Telemetry Card in sidebar list
    if (geoList) {
      const card = document.createElement("div");
      card.className = "geo-ip-item";
      card.innerHTML = `
        <div class="geo-ip-top">
          <span class="geo-ip-addr">${escapeHTML(item.ip)}</span>
          ${typeof renderThreatBadge === "function" ? renderThreatBadge(riskBadgeClass) : `<span class="threat-badge badge-${riskBadgeClass.toLowerCase()}">${riskBadgeClass}</span>`}
        </div>
        <div class="geo-ip-meta">
          <span><strong>Host:</strong> ${escapeHTML(item.label || item.ip)}</span>
          <span><strong>Type:</strong> ${escapeHTML((item.type || 'host').replace(/_/g, ' '))} · <strong>Loc:</strong> ${escapeHTML(locString)}</span>
          <span><strong>ISP:</strong> ${escapeHTML(item.isp || item.organization || 'Unknown')}</span>
        </div>
      `;
      card.addEventListener("click", () => {
        threatMap.setView([item.latitude, item.longitude], 7);
        marker.openPopup();
      });
      geoList.appendChild(card);
    }
  });

  // Polyline if current analysis has multiple connected hops
  if (activeHopCoords.length >= 2) {
    const polyline = L.polyline(activeHopCoords, {
      color: "#00f5ff",
      weight: 2,
      dashArray: "6, 8",
      opacity: 0.8,
    }).addTo(threatMap);
    threatMapPolylines.push(polyline);
  }

  // Adjust bounds to view all markers
  if (latLngBounds.length > 0) {
    if (latLngBounds.length === 1) {
      threatMap.setView(latLngBounds[0], 5);
    } else {
      threatMap.fitBounds(latLngBounds, { padding: [40, 40], maxZoom: 10 });
    }
  }
}

// ── Global Search Filter ────────────────────────────────────────────────────

function initGlobalSearch() {
  const searchInput = document.getElementById("global-search-input");
  if (!searchInput) return;

  searchInput.addEventListener("input", (e) => {
    const q = e.target.value.toLowerCase().trim();
    const rows = document.querySelectorAll("#dash-analysis-tbody tr:not(#empty-analysis-row)");
    rows.forEach(row => {
      const text = row.textContent.toLowerCase();
      row.style.display = text.includes(q) ? "" : "none";
    });

    const feedItems = document.querySelectorAll(".threat-feed-item");
    feedItems.forEach(item => {
      const text = item.textContent.toLowerCase();
      item.style.display = text.includes(q) ? "" : "none";
    });
  });

  // Keyboard shortcut Cmd+K / Ctrl+K
  window.addEventListener("keydown", (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
      e.preventDefault();
      searchInput.focus();
    }
  });
}

// ── Settings Model Health Checker ───────────────────────────────────────────

async function refreshModelHealth() {
  const msgBadge = document.getElementById("health-msg-badge");
  const urlBadge = document.getElementById("health-url-badge");
  const emailBadge = document.getElementById("health-email-badge");
  const callBadge = document.getElementById("health-call-badge");
  const videoBadge = document.getElementById("health-video-badge");

  try {
    const res = await fetch(`${API_BASE}/health`);
    if (!res.ok) throw new Error("Health check failed");
    const data = await res.json();
    const models = data.models || {};

    const setBadge = (el, ok) => {
      if (!el) return;
      el.textContent = ok ? "ONLINE" : "UNAVAILABLE";
      el.className = ok ? "health-badge health-ok" : "health-badge health-warn";
    };

    setBadge(msgBadge, models.message ?? true);
    setBadge(urlBadge, models.url ?? true);
    setBadge(emailBadge, models.email ?? true);
    setBadge(callBadge, models.call ?? true);
    setBadge(videoBadge, models.video ?? true);
  } catch (e) {
    [msgBadge, urlBadge, emailBadge, callBadge, videoBadge].forEach(b => {
      if (b) {
        b.textContent = "OFFLINE";
        b.className = "health-badge health-warn";
      }
    });
  }
}

document.getElementById("btn-refresh-health")?.addEventListener("click", refreshModelHealth);

// ── Tab Navigation for Unified Detection View ───────────────────────────────

const tabButtons = document.querySelectorAll(".tab");
const tabPanels = document.querySelectorAll(".tab-panel");

function switchTab(targetTab) {
  tabButtons.forEach(b => b.classList.remove("active"));
  tabPanels.forEach(p => p.classList.remove("active"));

  const btn = document.querySelector(`.tab[data-tab="${targetTab}"]`);
  const panel = document.getElementById(`panel-${targetTab}`);

  if (btn && panel) {
    btn.classList.add("active");
    panel.classList.add("active");
  }
}

tabButtons.forEach(btn => {
  btn.addEventListener("click", () => {
    const tabName = btn.dataset.tab;
    switchTab(tabName);
  });
});

// ── Sample Buttons Handler ──────────────────────────────────────────────────

function initSampleButtons() {
  // Detection view samples
  document.querySelectorAll(".sample-btn[data-sample]").forEach(btn => {
    btn.addEventListener("click", () => {
      const panel = btn.closest(".tab-panel");
      const textarea = panel?.querySelector(".textarea");
      const textInput = panel?.querySelector(".text-input");
      const target = textarea || textInput;
      if (target) {
        target.value = btn.dataset.sample;
        target.focus();
      }
    });
  });

  // Dynamic i18n email samples in detection panel
  document.getElementById("sample-email-phish")?.addEventListener("click", () => {
    const s = getLocalizedSamples().email_phish;
    const subj = document.getElementById("email-subject");
    const sender = document.getElementById("email-sender");
    const body = document.getElementById("email-body");
    if (subj) subj.value = s.subject;
    if (sender) sender.value = s.sender;
    if (body) body.value = s.body;
  });

  document.getElementById("sample-email-safe")?.addEventListener("click", () => {
    const s = getLocalizedSamples().email_safe;
    const subj = document.getElementById("email-subject");
    const sender = document.getElementById("email-sender");
    const body = document.getElementById("email-body");
    if (subj) subj.value = s.subject;
    if (sender) sender.value = s.sender;
    if (body) body.value = s.body;
  });

  // Dynamic i18n call samples in detection panel
  document.getElementById("sample-call-scam")?.addEventListener("click", () => {
    const txt = document.getElementById("call-transcript-input");
    if (txt) txt.value = getLocalizedSamples().call_scam;
  });

  document.getElementById("sample-call-safe")?.addEventListener("click", () => {
    const txt = document.getElementById("call-transcript-input");
    if (txt) txt.value = getLocalizedSamples().call_safe;
  });

  // V2 Dedicated View Samples
  document.getElementById("v2-sample-email-phish")?.addEventListener("click", () => {
    const s = getLocalizedSamples().email_phish;
    const subj = document.getElementById("email-subject-v2");
    const sender = document.getElementById("email-sender-v2");
    const body = document.getElementById("email-body-v2");
    if (subj) subj.value = s.subject;
    if (sender) sender.value = s.sender;
    if (body) body.value = s.body;
  });

  document.getElementById("v2-sample-email-safe")?.addEventListener("click", () => {
    const s = getLocalizedSamples().email_safe;
    const subj = document.getElementById("email-subject-v2");
    const sender = document.getElementById("email-sender-v2");
    const body = document.getElementById("email-body-v2");
    if (subj) subj.value = s.subject;
    if (sender) sender.value = s.sender;
    if (body) body.value = s.body;
  });

  document.getElementById("v2-sample-call-scam")?.addEventListener("click", () => {
    const txt = document.getElementById("v2-call-transcript");
    if (txt) txt.value = getLocalizedSamples().call_scam;
  });

  document.getElementById("v2-sample-call-safe")?.addEventListener("click", () => {
    const txt = document.getElementById("v2-call-transcript");
    if (txt) txt.value = getLocalizedSamples().call_safe;
  });

  document.getElementById("v2-sample-url-phish")?.addEventListener("click", () => {
    const inp = document.getElementById("v2-url-input");
    if (inp) inp.value = getLocalizedSamples().url_phish;
  });

  document.getElementById("v2-sample-url-safe")?.addEventListener("click", () => {
    const inp = document.getElementById("v2-url-input");
    if (inp) inp.value = getLocalizedSamples().url_safe;
  });
}

// ── Dropzone File Binding Helper ────────────────────────────────────────────

function setupDropzone(dropzoneId, inputId, previewId) {
  const dropzone = document.getElementById(dropzoneId);
  const input = document.getElementById(inputId);
  const preview = document.getElementById(previewId);
  if (!dropzone || !input) return;

  const btn = dropzone.querySelector(".upload-btn");
  if (btn) {
    btn.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      input.click();
    });
  }

  dropzone.addEventListener("click", (e) => {
    if (e.target !== input && !e.target.closest(".upload-btn") && !e.target.closest(".file-preview-clear")) {
      input.click();
    }
  });

  const renderPreview = (file) => {
    if (!preview) return;
    if (file) {
      preview.hidden = false;
      preview.innerHTML = `
        <span class="file-preview-name">✓ Selected: ${escapeHTML(file.name)} (${(file.size / 1024).toFixed(1)} KB)</span>
        <button type="button" class="file-preview-clear" title="Remove file">✕</button>
      `;
      preview.querySelector(".file-preview-clear")?.addEventListener("click", (e) => {
        e.preventDefault();
        e.stopPropagation();
        input.value = "";
        preview.hidden = true;
        preview.innerHTML = "";
      });
    } else {
      preview.hidden = true;
      preview.innerHTML = "";
    }
  };

  input.addEventListener("change", () => {
    const file = input.files[0];
    renderPreview(file);
  });

  dropzone.addEventListener("dragover", (e) => {
    e.preventDefault();
    e.stopPropagation();
    dropzone.classList.add("drag-over");
  });

  dropzone.addEventListener("dragleave", (e) => {
    e.preventDefault();
    e.stopPropagation();
    dropzone.classList.remove("drag-over");
  });

  dropzone.addEventListener("drop", (e) => {
    e.preventDefault();
    e.stopPropagation();
    dropzone.classList.remove("drag-over");
    const file = e.dataTransfer.files[0];
    if (file) {
      input.files = e.dataTransfer.files;
      renderPreview(file);
    }
  });
}

// ── Scanning HUD Overlay ────────────────────────────────────────────────────

function startScanner(customStatus) {
  const overlay = document.getElementById("scanning-overlay");
  const status = document.getElementById("scanning-status");
  if (!overlay) return;

  const phrases = [
    "Extracting feature vectors & threat tokens...",
    "Scanning NLP syntactic & urgency heuristics...",
    "Verifying cryptographic signatures & domain authority...",
    "Evaluating deepfake facial distortion tensors...",
    "Generating explainable threat defense dossier...",
  ];

  if (status) status.textContent = customStatus || phrases[0];
  overlay.hidden = false;

  let i = 0;
  clearInterval(scanInterval);
  scanInterval = setInterval(() => {
    i = (i + 1) % phrases.length;
    if (status && !customStatus) status.textContent = phrases[i];
  }, 750);
}

function stopScanner() {
  clearInterval(scanInterval);
  const overlay = document.getElementById("scanning-overlay");
  if (overlay) overlay.hidden = true;
}

// ── Network Fetch API Wrappers ──────────────────────────────────────────────

async function postJSON(endpoint, payload) {
  const res = await fetch(`${API_BASE}${endpoint}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || `Analysis request failed with HTTP ${res.status}`);
  }
  return await res.json();
}

async function postForm(endpoint, formData) {
  const res = await fetch(`${API_BASE}${endpoint}`, {
    method: "POST",
    body: formData,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || `File upload failed with HTTP ${res.status}`);
  }
  return await res.json();
}

// ── Primary Analysis Handlers ───────────────────────────────────────────────

async function analyzeMessage(customText) {
  const text = customText || document.getElementById("msg-input")?.value?.trim();
  if (!text) {
    showError("Please enter message content to analyze.");
    return;
  }
  startScanner("Analyzing message text & scam intent...");
  try {
    const data = await postJSON("/api/analyze/message", { text });
    renderResults(data, "message", text);
  } catch (err) {
    showError(err.message);
  }
}

async function analyzeUrl(customUrl) {
  const url = customUrl || document.getElementById("url-input")?.value?.trim() || document.getElementById("v2-url-input")?.value?.trim();
  if (!url) {
    showError("Please enter a URL to analyze.");
    return;
  }
  startScanner("Inspecting URL lexicals, DNS & IP reputation...");
  try {
    const data = await postJSON("/api/analyze/url", { url });
    renderResults(data, "url", url);
  } catch (err) {
    showError(err.message);
  }
}

async function analyzeImage(customFile, isV2 = false) {
  const fileInput = isV2 ? document.getElementById("v2-file-image") : document.getElementById("file-image");
  const fallbackInput = isV2 ? document.getElementById("file-image") : document.getElementById("v2-file-image");
  const file = customFile || fileInput?.files?.[0] || fallbackInput?.files?.[0];
  if (!file) {
    showError("Please select an image file to analyze.");
    return;
  }
  startScanner("Running OCR & image scam forensics...");
  const fd = new FormData();
  fd.append("file", file);
  try {
    const data = await postForm("/api/analyze/image", fd);
    renderResults(data, "image", file.name);
  } catch (err) {
    showError(err.message);
  }
}

async function analyzeVideo(customFile, isV2 = false) {
  const fileInput = isV2 ? document.getElementById("v2-file-video") : document.getElementById("file-video");
  const fallbackInput = isV2 ? document.getElementById("file-video") : document.getElementById("v2-file-video");
  const file = customFile || fileInput?.files?.[0] || fallbackInput?.files?.[0];
  if (!file) {
    showError("Please select a video file for deepfake analysis.");
    return;
  }
  startScanner("Extracting video frames & evaluating neural face models...");
  const fd = new FormData();
  fd.append("file", file);
  try {
    const data = await postForm("/api/analyze/video", fd);
    renderResults(data, "video", file.name);
  } catch (err) {
    showError(err.message);
  }
}

async function analyzeEmail(isV2 = false) {
  const fileInput = isV2 ? document.getElementById("v2-file-email") : document.getElementById("file-email");
  const fallbackInput = isV2 ? document.getElementById("file-email") : document.getElementById("v2-file-email");
  const file = fileInput?.files?.[0] || fallbackInput?.files?.[0];

  if (file) {
    startScanner("Parsing .eml file headers, SPF, DKIM & DMARC...");
    const fd = new FormData();
    fd.append("file", file);
    try {
      const data = await postForm("/api/analyze/email/file", fd);
      renderResults(data, "email", file.name);
    } catch (err) {
      showError(err.message);
    }
    return;
  }

  const subject = isV2
    ? (document.getElementById("email-subject-v2")?.value?.trim() || "")
    : (document.getElementById("email-subject")?.value?.trim() || "");
  const sender = isV2
    ? (document.getElementById("email-sender-v2")?.value?.trim() || "")
    : (document.getElementById("email-sender")?.value?.trim() || "");
  const body = isV2
    ? (document.getElementById("email-body-v2")?.value?.trim() || "")
    : (document.getElementById("email-body")?.value?.trim() || "");

  if (!body && !subject) {
    showError("Please enter email body content or upload an .eml file.");
    return;
  }

  startScanner("Analyzing email subject, declared sender & threat tokens...");
  try {
    const data = await postJSON("/api/analyze/email", { subject, sender, body });
    renderResults(data, "email", subject || sender || body.slice(0, 50));
  } catch (err) {
    showError(err.message);
  }
}

async function analyzeCall(isV2 = false) {
  const fileInput = isV2 ? document.getElementById("v2-file-call") : document.getElementById("file-call");
  const fallbackInput = isV2 ? document.getElementById("file-call") : document.getElementById("v2-file-call");
  const file = fileInput?.files?.[0] || fallbackInput?.files?.[0];

  if (file) {
    startScanner("Transcribing audio call recording & analyzing vishing cues...");
    const fd = new FormData();
    fd.append("file", file);
    try {
      const data = await postForm("/api/analyze/call", fd);
      renderResults(data, "call", file.name);
    } catch (err) {
      showError(err.message);
    }
    return;
  }

  const transcriptInput = isV2
    ? document.getElementById("v2-call-transcript")
    : document.getElementById("call-transcript-input");
  const text = transcriptInput?.value?.trim();

  if (!text) {
    showError("Please upload a call recording or paste a call transcript.");
    return;
  }

  startScanner("Analyzing call conversation transcript for vishing coercion...");
  try {
    const data = await postJSON("/api/analyze/call/text", { transcript: text });
    renderResults(data, "call", text.slice(0, 60));
  } catch (err) {
    showError(err.message);
  }
}

// Wire analysis buttons
function initAnalysisTriggers() {
  document.getElementById("btn-message")?.addEventListener("click", () => analyzeMessage());
  document.getElementById("btn-url")?.addEventListener("click", () => analyzeUrl());
  document.getElementById("btn-image")?.addEventListener("click", () => analyzeImage(null, false));
  document.getElementById("btn-video")?.addEventListener("click", () => analyzeVideo(null, false));
  document.getElementById("btn-email")?.addEventListener("click", () => analyzeEmail(false));
  document.getElementById("btn-call")?.addEventListener("click", () => analyzeCall(false));

  // V2 Forensic Buttons
  document.getElementById("v2-btn-email")?.addEventListener("click", () => analyzeEmail(true));
  document.getElementById("v2-btn-call")?.addEventListener("click", () => analyzeCall(true));
  document.getElementById("v2-btn-image")?.addEventListener("click", () => analyzeImage(null, true));
  document.getElementById("v2-btn-video")?.addEventListener("click", () => analyzeVideo(null, true));
  document.getElementById("v2-btn-url")?.addEventListener("click", () => analyzeUrl());
}

// ── Modal Rendering & Dossier Presentation ──────────────────────────────────

function openResultsModal() {
  const modal = document.getElementById("results-modal");
  if (modal) {
    modal.hidden = false;
    document.body.style.overflow = "hidden";
  }
}

function closeResultsModal() {
  const modal = document.getElementById("results-modal");
  if (modal) {
    modal.hidden = true;
    document.body.style.overflow = "";
  }
}

document.getElementById("btn-close-modal")?.addEventListener("click", closeResultsModal);
document.getElementById("btn-footer-close")?.addEventListener("click", closeResultsModal);
document.getElementById("modal-backdrop")?.addEventListener("click", closeResultsModal);
window.addEventListener("keydown", (e) => {
  if (e.key === "Escape") closeResultsModal();
});

function renderResults(data, modality, preview) {
  stopScanner();
  currentAnalysisData = data;

  const risk = data.risk_assessment || {};
  const score = risk.final_score ?? risk.score ?? data.analysis?.probability ?? data.analysis?.scam_probability ?? 0;
  const level = (risk.risk_level || risk.level || (score >= 60 ? "HIGH" : (score >= 30 ? "MEDIUM" : "LOW"))).toUpperCase();
  const verdict = data.final_analysis?.recommendation || data.recommendation || risk.verdict || "Follow security protocols.";
  const classification = data.analysis?.classification || data.classification || level;

  // Title & Metadata
  const metaEl = document.getElementById("results-meta");
  if (metaEl) {
    metaEl.textContent = `Modality: ${modality.toUpperCase()} · Classification: ${classification} · ${new Date().toLocaleTimeString()}`;
  }

  // Score Dial & Arc Animation
  animateScoreArc(score);

  const badgeEl = document.getElementById("risk-badge");
  if (badgeEl) {
    badgeEl.textContent = level;
    badgeEl.className = `risk-badge ${level}`;
  }

  const recEl = document.getElementById("recommendation-text");
  if (recEl) recEl.textContent = verdict;

  // Classification Pill
  const pillEl = document.getElementById("classification-pill");
  if (pillEl) {
    pillEl.textContent = classification.toUpperCase();
    pillEl.className = `classification-pill ${level}`;
  }

  // Why Suspicious Summary
  const whySummaryEl = document.getElementById("explanation-summary");
  const whySummary = data.final_analysis?.explanation_summary || data.explanation || "";
  if (whySummaryEl) whySummaryEl.textContent = whySummary;

  // Evidence Cards
  const evidenceGrid = document.getElementById("evidence-cards-grid");
  if (evidenceGrid) {
    evidenceGrid.innerHTML = "";
    const evidenceList = data.final_analysis?.evidence || data.analysis?.reasons || [];
    evidenceList.forEach(ev => {
      const card = document.createElement("div");
      card.className = "evidence-card";
      card.innerHTML = `
        <div class="evidence-card-title">🚨 Detected Pattern</div>
        <div class="evidence-card-desc">${escapeHTML(ev)}</div>
      `;
      evidenceGrid.appendChild(card);
    });
  }

  // Scam Digital DNA Component
  const dnaContainer = document.getElementById("digital-dna-container");
  if (dnaContainer && window.SatyaComponents && window.SatyaComponents.renderScamDigitalDNA) {
    window.SatyaComponents.renderScamDigitalDNA(dnaContainer, data.final_analysis?.digital_dna || {
      dna_id: data.analysis_id || "SATYA-DNA-01",
      scam_type: classification,
      risk_score: score,
      risk_level: level,
      attack_patterns: data.analysis?.indicators || ["Urgency", "Credential Risk"],
      evidence: data.final_analysis?.evidence || [],
    }, true);
  }

  // Recommended Actions (Do vs Don't)
  const doList = document.getElementById("immediate-actions-list");
  const avoidList = document.getElementById("avoid-actions-list");
  if (doList) {
    doList.innerHTML = "";
    const dos = data.final_analysis?.recommended_actions?.immediate_actions || [
      "Do not reply or click any provided links.",
      "Verify the sender directly through official channels.",
      "Report incident to Cyber Crime helpline 1930.",
    ];
    dos.forEach(d => {
      const li = document.createElement("li");
      li.textContent = d;
      doList.appendChild(li);
    });
  }

  if (avoidList) {
    avoidList.innerHTML = "";
    const donts = data.final_analysis?.recommended_actions?.avoid_actions || [
      "Do not share OTP, PIN, or password under any circumstance.",
      "Do not install remote desktop apps (AnyDesk, TeamViewer).",
      "Do not transfer funds to temporary 'verification accounts'.",
    ];
    donts.forEach(d => {
      const li = document.createElement("li");
      li.textContent = d;
      avoidList.appendChild(li);
    });
  }

  // Verification Steps
  const verifyList = document.getElementById("verification-steps-list");
  if (verifyList) {
    verifyList.innerHTML = "";
    const steps = data.final_analysis?.how_to_verify || [
      "Check official URL prefix and ensure HTTPS is present.",
      "Call official customer support numbers listed on your card/statements.",
    ];
    steps.forEach(s => {
      const li = document.createElement("li");
      li.textContent = s;
      verifyList.appendChild(li);
    });
  }

  // Raw Indicators List
  const indList = document.getElementById("indicators-list");
  if (indList) {
    indList.innerHTML = "";
    const indicators = data.analysis?.indicators || data.indicators || [];
    if (indicators.length > 0) {
      indicators.forEach(ind => {
        const item = document.createElement("div");
        item.className = "indicator-item";
        item.textContent = `• ${ind}`;
        indList.appendChild(item);
      });
    } else {
      indList.innerHTML = "<p style='color:var(--text-muted);font-size:0.8rem;'>No explicit rule-based indicators flagged.</p>";
    }
  }

  // Transcript / Extracted Text
  const transCard = document.getElementById("transcript-card");
  const transText = document.getElementById("transcript-text");
  const extracted = data.analysis?.ocr_text || data.analysis?.transcript || data.analysis?.headers?.body_text;
  if (transCard && transText) {
    if (extracted) {
      transCard.hidden = false;
      transText.textContent = extracted;
    } else {
      transCard.hidden = true;
    }
  }

  // Technical Telemetry Raw JSON
  const rawEl = document.getElementById("raw-json");
  if (rawEl) rawEl.textContent = JSON.stringify(data, null, 2);

  // Add to Persistent History & Telemetry
  addHistory(modality, preview, score, level, data);

  // Open the Modal
  openResultsModal();
}

function animateScoreArc(targetScore) {
  const arc = document.getElementById("score-arc");
  const el = document.getElementById("score-number");
  if (!arc || !el) return;

  const arcLen = 220;
  let current = 0;
  const step = Math.max(1, Math.round(targetScore / 25));

  const interval = setInterval(() => {
    current = Math.min(current + step, targetScore);
    el.textContent = Math.round(current);
    arc.style.strokeDashoffset = arcLen - (arcLen * current / 100);
    if (current >= targetScore) clearInterval(interval);
  }, 20);
}

// ── Modal Actions (Print, Copy, Investigate in Copilot) ─────────────────────

document.getElementById("btn-copy-report")?.addEventListener("click", () => {
  if (!currentAnalysisData) return;
  const text = JSON.stringify(currentAnalysisData, null, 2);
  navigator.clipboard.writeText(text).then(() => {
    if (window.SatyaComponents && window.SatyaComponents.showToast) {
      window.SatyaComponents.showToast("Threat dossier copied to clipboard", "success");
    }
  });
});

document.getElementById("btn-print-report")?.addEventListener("click", () => {
  window.print();
});

document.getElementById("btn-modal-copilot")?.addEventListener("click", () => {
  if (!currentAnalysisData) return;
  const risk = currentAnalysisData.risk_assessment || {};
  const score = risk.final_score ?? 0;
  const level = risk.risk_level || "UNKNOWN";
  const id = currentAnalysisData.analysis_id || "SATYA-AN-01";

  closeResultsModal();
  openCopilotFloatingWindow();
  setCopilotActiveEvidence(id, "investigation", score, level, `Dossier ${id}`);
});

document.getElementById("btn-modal-view-map")?.addEventListener("click", () => {
  closeResultsModal();
  switchView("geo");
  setTimeout(() => {
    initOrRefreshThreatMap();
  }, 200);
});

// ── Error Helper ────────────────────────────────────────────────────────────

function showError(message) {
  stopScanner();
  if (window.SatyaComponents && window.SatyaComponents.showToast) {
    window.SatyaComponents.showToast(message, "error");
  } else {
    alert(message);
  }
}

function escapeHTML(str) {
  return String(str || "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

// ── AI Fraud Investigation Copilot Controls ─────────────────────────────────

let currentAnalysisId = null;
let currentEvidenceContext = null;

function setCopilotActiveEvidence(analysisId, modality, score, level, preview) {
  currentAnalysisId = analysisId;
  currentEvidenceContext = { analysisId, modality, score, level, preview };

  // Update floating widget evidence bar
  const floatStatus = document.getElementById("copilot-evidence-status-text");
  const floatClear = document.getElementById("btn-copilot-clear");
  const floatId = document.getElementById("copilot-active-id");
  const floatPill = document.getElementById("copilot-active-pill");

  if (floatStatus) floatStatus.textContent = `Evidence Dossier: ${analysisId}`;
  if (floatClear) floatClear.hidden = false;
  if (floatId) { floatId.hidden = false; floatId.textContent = analysisId; }
  if (floatPill) { floatPill.hidden = false; floatPill.textContent = `${score}/100 [${level}]`; }

  // Update full-view evidence bar
  const v2Status = document.getElementById("v2-copilot-status-text");
  const v2Clear = document.getElementById("v2-btn-copilot-clear");
  const v2Id = document.getElementById("v2-copilot-active-id");
  const v2Pill = document.getElementById("v2-copilot-active-pill");

  if (v2Status) v2Status.textContent = `Evidence Dossier: ${analysisId}`;
  if (v2Clear) v2Clear.hidden = false;
  if (v2Id) { v2Id.hidden = false; v2Id.textContent = analysisId; }
  if (v2Pill) { v2Pill.hidden = false; v2Pill.textContent = `${score}/100 [${level}]`; }
}

function clearCopilotEvidence() {
  currentAnalysisId = null;
  currentEvidenceContext = null;

  const floatStatus = document.getElementById("copilot-evidence-status-text");
  const floatClear = document.getElementById("btn-copilot-clear");
  if (floatStatus) floatStatus.textContent = "Mode: General Cyber Threat Knowledge Base";
  if (floatClear) floatClear.hidden = true;

  const v2Status = document.getElementById("v2-copilot-status-text");
  const v2Clear = document.getElementById("v2-btn-copilot-clear");
  if (v2Status) v2Status.textContent = "Mode: General Cyber Threat Knowledge Base";
  if (v2Clear) v2Clear.hidden = true;

  appendAssistantMessage({
    answer: "Evidence cleared. Now operating in **General Cyber Threat Intelligence Knowledge Base** mode.",
  });
}

document.getElementById("btn-copilot-clear")?.addEventListener("click", clearCopilotEvidence);
document.getElementById("v2-btn-copilot-clear")?.addEventListener("click", clearCopilotEvidence);

function openCopilotFloatingWindow() {
  const win = document.getElementById("copilot-floating-window");
  const fab = document.getElementById("copilot-fab");
  const navBtn = document.getElementById("nav-copilot-btn");
  if (win) {
    win.hidden = false;
    win.classList.add("active");
  }
  if (fab) fab.classList.add("active");
  if (navBtn) navBtn.classList.add("active");
}

function closeCopilotFloatingWindow() {
  const win = document.getElementById("copilot-floating-window");
  const fab = document.getElementById("copilot-fab");
  const navBtn = document.getElementById("nav-copilot-btn");
  if (win) {
    win.hidden = true;
    win.classList.remove("active");
  }
  if (fab) fab.classList.remove("active");
  if (navBtn) navBtn.classList.remove("active");
}

function toggleCopilotFloatingWindow() {
  const win = document.getElementById("copilot-floating-window");
  if (win) {
    if (win.hidden) {
      openCopilotFloatingWindow();
      setTimeout(() => document.getElementById("copilot-input")?.focus(), 100);
    } else {
      closeCopilotFloatingWindow();
    }
  }
}

document.getElementById("copilot-fab")?.addEventListener("click", toggleCopilotFloatingWindow);
document.getElementById("nav-copilot-btn")?.addEventListener("click", toggleCopilotFloatingWindow);
document.getElementById("btn-copilot-close")?.addEventListener("click", closeCopilotFloatingWindow);
document.getElementById("btn-copilot-minimize")?.addEventListener("click", closeCopilotFloatingWindow);

// Copilot Chat Messaging Logic
async function sendCopilotMessage(userMessage) {
  if (!userMessage || !userMessage.trim()) return;
  const msgText = userMessage.trim();

  appendUserMessage(msgText);

  // Clear inputs
  const floatInput = document.getElementById("copilot-input");
  const v2Input = document.getElementById("v2-copilot-input");
  if (floatInput) floatInput.value = "";
  if (v2Input) v2Input.value = "";

  const typingId = appendTypingIndicator();

  try {
    const res = await fetch(`${API_BASE}/api/chat`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        message: msgText,
        analysis_id: currentAnalysisId,
      }),
    });

    removeTypingIndicator(typingId);

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Chat query failed with status ${res.status}`);
    }

    const data = await res.json();
    appendAssistantMessage(data);
  } catch (err) {
    removeTypingIndicator(typingId);
    appendAssistantMessage({
      answer: `⚠️ Unable to complete copilot query: ${err.message}`,
    });
  }
}

function appendUserMessage(text) {
  const containers = [
    document.getElementById("copilot-messages"),
    document.getElementById("v2-copilot-messages"),
  ];

  containers.forEach(box => {
    if (!box) return;
    const msg = document.createElement("div");
    msg.className = "chat-msg user-msg";
    msg.innerHTML = `
      <div class="msg-bubble">
        <div class="msg-header">
          <span class="msg-author" style="color:#ffffff;">You</span>
        </div>
        <div class="msg-body">${escapeHTML(text)}</div>
      </div>
      <div class="msg-avatar">👤</div>
    `;
    box.appendChild(msg);
    box.scrollTop = box.scrollHeight;
  });
}

function appendAssistantMessage(data) {
  const containers = [
    document.getElementById("copilot-messages"),
    document.getElementById("v2-copilot-messages"),
  ];

  containers.forEach(box => {
    if (!box) return;
    const msg = document.createElement("div");
    msg.className = "chat-msg assistant-msg";
    msg.innerHTML = `
      <div class="msg-avatar">🤖</div>
      <div class="msg-bubble">
        <div class="msg-header">
          <span class="msg-author">SATYA AI Copilot</span>
          <span class="msg-badge">RAG Intelligence</span>
        </div>
        <div class="msg-body">${formatMarkdown(data.answer || "")}</div>
      </div>
    `;
    box.appendChild(msg);
    box.scrollTop = box.scrollHeight;
  });
}

let typingCount = 0;
function appendTypingIndicator() {
  typingCount++;
  const id = `typing-indicator-${typingCount}`;
  const containers = [
    document.getElementById("copilot-messages"),
    document.getElementById("v2-copilot-messages"),
  ];

  containers.forEach(box => {
    if (!box) return;
    const msg = document.createElement("div");
    msg.className = "chat-msg assistant-msg typing-msg";
    msg.id = id;
    msg.innerHTML = `
      <div class="msg-avatar">🤖</div>
      <div class="msg-bubble" style="padding: 6px 14px;">
        <span class="pulse-dot"></span> Thinking...
      </div>
    `;
    box.appendChild(msg);
    box.scrollTop = box.scrollHeight;
  });
  return id;
}

function removeTypingIndicator(id) {
  document.querySelectorAll(`#${id}`).forEach(el => el.remove());
}

function formatMarkdown(text) {
  if (!text) return "";
  let html = escapeHTML(text);
  html = html.replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>");
  html = html.replace(/\*(.*?)\*/g, "<em>$1</em>");
  html = html.replace(/\n\n/g, "<br/><br/>");
  html = html.replace(/\n/g, "<br/>");
  return html;
}

// Wire forms & question chips for Copilot
function initCopilotControls() {
  document.getElementById("copilot-form")?.addEventListener("submit", (e) => {
    e.preventDefault();
    const val = document.getElementById("copilot-input")?.value;
    sendCopilotMessage(val);
  });

  document.getElementById("v2-copilot-form")?.addEventListener("submit", (e) => {
    e.preventDefault();
    const val = document.getElementById("v2-copilot-input")?.value;
    sendCopilotMessage(val);
  });

  document.querySelectorAll("#copilot-chips .suggestion-chip, #v2-copilot-chips .suggestion-chip").forEach(chip => {
    chip.addEventListener("click", () => {
      const q = chip.dataset.query || chip.textContent;
      sendCopilotMessage(q);
    });
  });

  // Copilot Upload Drawer & File Attachment
  const drawer = document.getElementById("copilot-upload-drawer");
  const toggleBtn = document.getElementById("btn-toggle-upload");
  if (toggleBtn && drawer) {
    toggleBtn.addEventListener("click", () => {
      drawer.hidden = !drawer.hidden;
    });
  }

  // Copilot Mode tabs in drawer (text, url, file)
  document.querySelectorAll(".copilot-mode-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".copilot-mode-btn").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      const mode = btn.dataset.mode || "text";
      const pText = document.getElementById("copilot-mode-text");
      const pUrl = document.getElementById("copilot-mode-url");
      const pFile = document.getElementById("copilot-mode-file");
      if (pText) pText.style.display = mode === "text" ? "block" : "none";
      if (pUrl) pUrl.style.display = mode === "url" ? "block" : "none";
      if (pFile) pFile.style.display = mode === "file" ? "block" : "none";
    });
  });

  // Analyze & Attach button in Copilot drawer
  const attachBtn = document.getElementById("btn-copilot-analyze-attach");
  if (attachBtn) {
    attachBtn.addEventListener("click", async () => {
      const activeModeBtn = document.querySelector(".copilot-mode-btn.active");
      const mode = activeModeBtn?.dataset.mode || "text";

      if (mode === "file") {
        const fileInput = document.getElementById("copilot-file-input");
        const file = fileInput?.files?.[0];
        if (!file) {
          showError("Please select a file to attach to Copilot.");
          return;
        }

        const ext = file.name.slice(file.name.lastIndexOf(".")).toLowerCase();
        const spinner = document.getElementById("copilot-attach-spinner");
        if (spinner) spinner.hidden = false;
        attachBtn.disabled = true;

        const fd = new FormData();
        fd.append("file", file);

        try {
          let data = null;
          let modality = "file";

          if ([".png", ".jpg", ".jpeg", ".webp", ".bmp", ".tiff"].includes(ext)) {
            modality = "image";
            data = await postForm("/api/analyze/image", fd);
          } else if ([".mp3", ".wav", ".m4a", ".ogg", ".webm", ".flac", ".aac"].includes(ext)) {
            modality = "call";
            data = await postForm("/api/analyze/call", fd);
          } else if ([".mp4", ".avi", ".mov", ".mkv", ".flv"].includes(ext)) {
            modality = "video";
            data = await postForm("/api/analyze/video", fd);
          } else if ([".eml", ".msg", ".txt"].includes(ext)) {
            modality = "email";
            data = await postForm("/api/analyze/email/file", fd);
          } else {
            throw new Error(`Unsupported file type '${ext}'`);
          }

          const risk = data.risk_assessment || {};
          const score = risk.final_score ?? risk.score ?? 0;
          const level = (risk.risk_level || (score >= 60 ? "HIGH" : (score >= 30 ? "MEDIUM" : "LOW"))).toUpperCase();
          const analysisId = data.analysis_id || "SATYA-COPILOT";

          setCopilotActiveEvidence(analysisId, modality, score, level, file.name);

          appendUserMessage(`[Attached Evidence File: ${file.name}]`);
          appendAssistantMessage({
            answer: `I have analyzed **${escapeHTML(file.name)}** (*${modality.toUpperCase()}*).\n\n• **Risk Assessment**: ${score}/100 [**${level}**]\n• **Analysis ID**: \`${analysisId}\`\n\nThis dossier is now attached as active evidence. What specific insights, indicators, or recommendations would you like me to clarify?`
          });

          if (drawer) drawer.hidden = true;
          fileInput.value = "";
          const prev = document.getElementById("copilot-file-preview");
          if (prev) { prev.hidden = true; prev.innerHTML = ""; }

        } catch (err) {
          showError(`Failed to analyze attached file: ${err.message}`);
        } finally {
          if (spinner) spinner.hidden = true;
          attachBtn.disabled = false;
        }
      } else if (mode === "url") {
        const url = document.getElementById("copilot-url-input")?.value?.trim();
        if (!url) {
          showError("Please enter a URL to analyze.");
          return;
        }
        try {
          const data = await postJSON("/api/analyze/url", { url });
          const risk = data.risk_assessment || {};
          const score = risk.final_score ?? 0;
          const level = (risk.risk_level || "UNKNOWN").toUpperCase();
          const analysisId = data.analysis_id || "SATYA-COPILOT";

          setCopilotActiveEvidence(analysisId, "url", score, level, url);
          appendUserMessage(`[Analyzed URL: ${url}]`);
          appendAssistantMessage({
            answer: `I have analyzed the URL: **${escapeHTML(url)}**.\n\n• **Risk Assessment**: ${score}/100 [**${level}**]\n• **Classification**: ${escapeHTML(data.analysis?.prediction || level)}\n• **Analysis ID**: \`${analysisId}\`\n\nThis URL is now linked as active evidence.`
          });
          if (drawer) drawer.hidden = true;
        } catch (err) {
          showError(`URL analysis failed: ${err.message}`);
        }
      } else if (mode === "text") {
        const text = document.getElementById("copilot-text-input")?.value?.trim();
        if (!text) {
          showError("Please enter text or message to analyze.");
          return;
        }
        try {
          const data = await postJSON("/api/analyze/message", { text });
          const risk = data.risk_assessment || {};
          const score = risk.final_score ?? 0;
          const level = (risk.risk_level || "UNKNOWN").toUpperCase();
          const analysisId = data.analysis_id || "SATYA-COPILOT";

          setCopilotActiveEvidence(analysisId, "message", score, level, text.slice(0, 50));
          appendUserMessage(`[Analyzed Text Snippet: ${text.slice(0, 60)}...]`);
          appendAssistantMessage({
            answer: `I have analyzed the text snippet.\n\n• **Risk Assessment**: ${score}/100 [**${level}**]\n• **Classification**: ${escapeHTML(data.analysis?.classification || level)}\n• **Analysis ID**: \`${analysisId}\`\n\nThis text is now linked as active evidence.`
          });
          if (drawer) drawer.hidden = true;
        } catch (err) {
          showError(`Text analysis failed: ${err.message}`);
        }
      }
    });
  }
}

// ── Application Bootstrap ───────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", () => {
  loadStoredHistory();
  initSidebarControls();
  initQuickActions();
  initSampleButtons();
  initAnalysisTriggers();
  initGlobalSearch();
  initCopilotControls();

  // Setup dropzones for both Detection view and V2 views
  setupDropzone("dropzone-email", "file-email", "preview-email");
  setupDropzone("dropzone-call", "file-call", "preview-call");
  setupDropzone("dropzone-image", "file-image", "preview-image");
  setupDropzone("dropzone-video", "file-video", "preview-video");

  setupDropzone("v2-dropzone-email", "v2-file-email", "v2-preview-email");
  setupDropzone("v2-dropzone-call", "v2-file-call", "v2-preview-call");
  setupDropzone("v2-dropzone-image", "v2-file-image", "v2-preview-image");
  setupDropzone("v2-dropzone-video", "v2-file-video", "v2-preview-video");
  setupDropzone("copilot-dropzone", "copilot-file-input", "copilot-file-preview");

  updateDashboardTelemetry();
  refreshModelHealth();
});
