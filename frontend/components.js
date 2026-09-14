/**
 * SATYA AI 3.0 — Modular Frontend Component Library
 * Implements ScamDigitalDNA, RiskSummary, EvidenceList, AttackIntent,
 * AttackFlow, MultimodalEvidence, RecommendedActions, FraudCopilot, and ModeToggle.
 */

const SatyaComponents = (() => {
  function escapeHtml(str) {
    if (!str) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function getPatternIcon(pattern) {
    const p = (pattern || "").toLowerCase();
    if (p.includes("urgenc")) return "🚨";
    if (p.includes("credential") || p.includes("otp")) return "🔐";
    if (p.includes("url") || p.includes("phish")) return "🔗";
    if (p.includes("impersonat") || p.includes("bank")) return "🏦";
    if (p.includes("social") || p.includes("kyc")) return "🪪";
    if (p.includes("financial") || p.includes("upi")) return "💳";
    if (p.includes("synthetic") || p.includes("deepfake")) return "🎬";
    if (p.includes("voice")) return "🎙️";
    return "⚡";
  }

  function getIntentIcon(goal) {
    const g = (goal || "").toLowerCase();
    if (g.includes("credential") || g.includes("password") || g.includes("login")) return "🔐";
    if (g.includes("otp") || g.includes("code")) return "📱";
    if (g.includes("money") || g.includes("financial") || g.includes("transfer")) return "💳";
    if (g.includes("kyc") || g.includes("identity") || g.includes("document") || g.includes("aadhaar")) return "🪪";
    if (g.includes("account") || g.includes("access")) return "💻";
    if (g.includes("malware") || g.includes("virus")) return "🦠";
    if (g.includes("website") || g.includes("redirect")) return "🔗";
    return "🎯";
  }

  // 1. ModeToggle
  function renderModeToggle(container, currentMode, onToggle) {
    if (!container) return;
    const isExpert = currentMode === "expert";
    container.innerHTML = `
      <div class="satya-mode-toggle">
        <span class="mode-toggle-label">View Mode:</span>
        <div class="mode-toggle-buttons">
          <button type="button" class="mode-btn ${!isExpert ? 'active' : ''}" data-mode="simple">
            <span>🔰</span> Simple Mode
          </button>
          <button type="button" class="mode-btn ${isExpert ? 'active' : ''}" data-mode="expert">
            <span>🔬</span> Expert Mode
          </button>
        </div>
      </div>
    `;

    container.querySelectorAll(".mode-btn").forEach(btn => {
      btn.addEventListener("click", () => {
        const mode = btn.dataset.mode;
        if (typeof onToggle === "function") onToggle(mode);
      });
    });
  }

  // 2. ScamDigitalDNA
  function renderScamDigitalDNA(container, dnaData, isExpert) {
    if (!container) return;
    if (!dnaData) {
      container.innerHTML = "";
      return;
    }

    const dnaId = dnaData.dna_id || "SAFE-VERIFIED-01";
    const scamType = dnaData.scam_type || "Verified Safe Content";
    const patterns = dnaData.attack_patterns || [];
    const evidenceItems = dnaData.evidence || [];
    const riskLevel = (dnaData.risk_level || "LOW").toUpperCase();
    const riskScore = dnaData.risk_score ?? 0;

    const patternChips = patterns.map(p => `
      <span class="dna-pattern-chip">
        <span class="pattern-icon">${getPatternIcon(p)}</span>
        <span>${escapeHtml(p)}</span>
      </span>
    `).join("");

    const evidenceListHtml = evidenceItems.map(ev => `
      <li class="dna-evidence-item">
        <span class="evidence-check">✓</span>
        <span>${escapeHtml(ev.replace(/^[✓\s]+/, ''))}</span>
      </li>
    `).join("");

    container.innerHTML = `
      <div class="result-card satya-dna-card">
        <div class="card-header flex-header">
          <div class="header-left">
            <span class="card-header-icon">🧬</span>
            <span>SCAM DIGITAL DNA</span>
          </div>
          <div class="dna-meta-badges">
            <span class="dna-risk-badge ${riskLevel.toLowerCase()}">${riskLevel} (${riskScore}/100)</span>
          </div>
        </div>

        <div class="dna-body-grid">
          <div class="dna-left-column">
            <div class="dna-id-box">
              <span class="dna-id-label">DNA ID:</span>
              <span class="dna-id-code">${escapeHtml(dnaId)}</span>
            </div>
            <div class="dna-scam-type">
              <span class="scam-type-label">Scam Type:</span>
              <span class="scam-type-value">${escapeHtml(scamType)}</span>
            </div>
            <div class="dna-patterns-section">
              <span class="patterns-label">Attack Pattern:</span>
              <div class="dna-patterns-wrap">${patternChips || '<span class="no-pattern">No malicious patterns detected</span>'}</div>
            </div>
          </div>

          <div class="dna-right-column">
            <span class="dna-evidence-label">Detected Evidence:</span>
            <ul class="dna-evidence-checklist">
              ${evidenceListHtml || '<li class="dna-evidence-item"><span class="evidence-check">✓</span><span>No threat indicators present</span></li>'}
            </ul>
          </div>
        </div>
      </div>
    `;
  }

  // 3. AttackIntent ("WHAT MAY THE ATTACKER WANT?")
  function renderAttackIntent(container, attackerGoals) {
    if (!container) return;
    const goals = attackerGoals || [];

    let chipsHtml = "";
    if (goals.length > 0) {
      chipsHtml = goals.map(goal => `
        <div class="intent-chip">
          <span class="intent-icon">${getIntentIcon(goal)}</span>
          <span class="intent-text">${escapeHtml(goal)}</span>
        </div>
      `).join("");
    } else {
      chipsHtml = `
        <div class="intent-chip safe">
          <span class="intent-icon">🛡️</span>
          <span class="intent-text">No malicious attacker intent detected</span>
        </div>
      `;
    }

    container.innerHTML = `
      <div class="result-card satya-intent-card">
        <div class="card-header">
          <span class="card-header-icon">🎯</span>
          <span>WHAT MAY THE ATTACKER WANT?</span>
        </div>
        <div class="intent-chips-grid">
          ${chipsHtml}
        </div>
      </div>
    `;
  }

  // 4. AttackFlow
  function renderAttackFlow(container, flowStages) {
    if (!container) return;
    const stages = flowStages || [];
    if (stages.length === 0) {
      container.innerHTML = "";
      return;
    }

    const stepsHtml = stages.map((st, idx) => `
      <div class="flow-step-card">
        <div class="flow-step-header">
          <span class="flow-step-num">Stage ${st.stage || (idx + 1)}</span>
          <span class="flow-step-icon">${st.icon || '⚡'}</span>
        </div>
        <div class="flow-step-title">${escapeHtml(st.title)}</div>
        <div class="flow-step-desc">${escapeHtml(st.desc)}</div>
      </div>
      ${idx < stages.length - 1 ? '<div class="flow-step-connector"><span>↓</span></div>' : ''}
    `).join("");

    container.innerHTML = `
      <div class="result-card satya-flow-card">
        <div class="card-header">
          <span class="card-header-icon">🔄</span>
          <span>ATTACK FLOW</span>
        </div>
        <div class="flow-sequence-wrap">
          ${stepsHtml}
        </div>
      </div>
    `;
  }

  // 5. MultimodalEvidence
  function renderMultimodalEvidence(container, multimodalData) {
    if (!container) return;
    const items = multimodalData || [];
    if (items.length === 0) {
      container.innerHTML = "";
      return;
    }

    const rowsHtml = items.map(item => `
      <tr class="multimodal-row">
        <td class="mod-name-cell">
          <span class="mod-status-dot active"></span>
          <strong>${escapeHtml(item.modality)}</strong>
        </td>
        <td class="mod-status-cell">
          <span class="mod-analyzed-badge">${escapeHtml(item.status)}</span>
        </td>
        <td class="mod-result-cell">
          <span class="mod-level-tag ${(item.risk_level || 'low').toLowerCase()}">
            ${escapeHtml(item.result)}
          </span>
        </td>
      </tr>
    `).join("");

    container.innerHTML = `
      <div class="result-card satya-multimodal-card">
        <div class="card-header">
          <span class="card-header-icon">📊</span>
          <span>MULTIMODAL EVIDENCE</span>
        </div>
        <table class="multimodal-table">
          <thead>
            <tr>
              <th>Modality Channel</th>
              <th>Pipeline Status</th>
              <th>Outcome / Level</th>
            </tr>
          </thead>
          <tbody>
            ${rowsHtml}
          </tbody>
        </table>
      </div>
    `;
  }

  // 6. RecommendedActions (Do vs Don't)
  function renderRecommendedActions(container, doList, avoidList) {
    if (!container) return;
    const actions = (doList && doList.length > 0)
      ? doList
      : ["Continue with caution", "Verify the sender independently"];
    const avoids = (avoidList && avoidList.length > 0)
      ? avoidList
      : ["Do not share sensitive information without verification"];

    const doItems = actions.map(a => `
      <li class="action-item do">
        <span class="action-item-icon">✓</span>
        <span>${escapeHtml(a)}</span>
      </li>
    `).join("");

    const avoidItems = avoids.map(av => `
      <li class="action-item avoid">
        <span class="action-item-icon">❌</span>
        <span>${escapeHtml(av)}</span>
      </li>
    `).join("");

    container.innerHTML = `
      <div class="actions-grid">
        <div class="result-card immediate-actions-card">
          <div class="card-header header-success">
            <span class="card-header-icon">✅</span>
            <span>WHAT SHOULD YOU DO?</span>
          </div>
          <ul class="action-items-list do-list">${doItems}</ul>
        </div>

        <div class="result-card avoid-actions-card">
          <div class="card-header header-danger">
            <span class="card-header-icon">❌</span>
            <span>DO NOT DO THIS</span>
          </div>
          <ul class="action-items-list avoid-list">${avoidItems}</ul>
        </div>
      </div>
    `;
  }

  // 7. FraudCopilot (Inline Interactive Chatbot)
  function renderFraudCopilot(container, analysisId) {
    if (!container) return;

    const quickQuestions = [
      "Why is this suspicious?",
      "What does the attacker want?",
      "What evidence was detected?",
      "What should I do now?",
      "Is this a phishing scam?",
      "How can I verify this safely?",
    ];

    const questionsHtml = quickQuestions.map(q => `
      <button type="button" class="copilot-chip-btn" data-question="${escapeHtml(q)}">
        ${escapeHtml(q)}
      </button>
    `).join("");

    container.innerHTML = `
      <div class="result-card satya-inline-copilot-card">
        <div class="copilot-header">
          <div class="copilot-header-title">
            <span class="copilot-bot-icon">🤖</span>
            <div>
              <h4>SATYA AI FRAUD INVESTIGATION COPILOT</h4>
              <p class="copilot-subtitle">Ask SatyaAI why this content is suspicious.</p>
            </div>
          </div>
          ${analysisId ? `<span class="copilot-context-badge">Dossier: ${escapeHtml(analysisId)}</span>` : ''}
        </div>

        <div class="copilot-quick-chips">
          ${questionsHtml}
        </div>

        <div class="copilot-messages-viewport" id="modal-copilot-messages">
          <div class="copilot-bubble assistant">
            <span class="bubble-avatar">🤖</span>
            <div class="bubble-content">
              Hello! I am your SatyaAI Copilot. Ask me questions about this analysis, or click any prompt above.
            </div>
          </div>
        </div>

        <form class="copilot-input-form" id="modal-copilot-form">
          <input type="text" class="copilot-input-field" id="modal-copilot-input"
            placeholder="Ask SatyaAI: What makes this message suspicious?..." />
          <button type="submit" class="copilot-send-btn" id="modal-copilot-send">
            <span>Send</span> ➔
          </button>
        </form>
      </div>
    `;

    const viewport = container.querySelector("#modal-copilot-messages");
    const form = container.querySelector("#modal-copilot-form");
    const input = container.querySelector("#modal-copilot-input");

    async function sendQuery(text) {
      if (!text || !text.trim()) return;
      const question = text.trim();
      input.value = "";

      // Append user bubble
      const userBubble = document.createElement("div");
      userBubble.className = "copilot-bubble user";
      userBubble.innerHTML = `
        <div class="bubble-content">${escapeHtml(question)}</div>
        <span class="bubble-avatar">👤</span>
      `;
      viewport.appendChild(userBubble);
      viewport.scrollTop = viewport.scrollHeight;

      // Append typing indicator
      const typingBubble = document.createElement("div");
      typingBubble.className = "copilot-bubble assistant typing";
      typingBubble.innerHTML = `
        <span class="bubble-avatar">🤖</span>
        <div class="bubble-content">
          <div class="typing-dots"><span></span><span></span><span></span></div>
        </div>
      `;
      viewport.appendChild(typingBubble);
      viewport.scrollTop = viewport.scrollHeight;

      try {
        const res = await (window.ChatAPI
          ? window.ChatAPI.sendChatMessage(question, analysisId)
          : fetch("/api/chat", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ message: question, analysis_id: analysisId }),
            }).then(r => r.json()));

        typingBubble.remove();

        const botBubble = document.createElement("div");
        botBubble.className = "copilot-bubble assistant";
        botBubble.innerHTML = `
          <span class="bubble-avatar">🤖</span>
          <div class="bubble-content">
            <p>${escapeHtml(res.answer || res.message || "Analysis evaluated.")}</p>
            ${res.sources && res.sources.length > 0 ? `
              <div class="bubble-sources">
                <span class="source-tag">📚 Source: ${res.sources.map(s => escapeHtml(s)).join(", ")}</span>
              </div>
            ` : ''}
          </div>
        `;
        viewport.appendChild(botBubble);
        viewport.scrollTop = viewport.scrollHeight;
      } catch (err) {
        typingBubble.remove();
        const errBubble = document.createElement("div");
        errBubble.className = "copilot-bubble assistant error";
        errBubble.innerHTML = `
          <span class="bubble-avatar">⚠️</span>
          <div class="bubble-content">
            Unable to fetch copilot response: ${escapeHtml(err.message)}
          </div>
        `;
        viewport.appendChild(errBubble);
        viewport.scrollTop = viewport.scrollHeight;
      }
    }

    form.addEventListener("submit", (e) => {
      e.preventDefault();
      sendQuery(input.value);
    });

    container.querySelectorAll(".copilot-chip-btn").forEach(btn => {
      btn.addEventListener("click", () => {
        sendQuery(btn.dataset.question);
      });
    });
  }

  // 8. Toast Notifications
  function showToast(message, type = "info", duration = 3500) {
    let container = document.getElementById("satya-toast-container");
    if (!container) {
      container = document.createElement("div");
      container.id = "satya-toast-container";
      container.className = "satya-toast-container";
      document.body.appendChild(container);
    }
    const icons = {
      success: "✓",
      error: "✕",
      warning: "⚠️",
      info: "ℹ️",
    };
    const toast = document.createElement("div");
    toast.className = `satya-toast toast-${type}`;
    toast.innerHTML = `
      <span class="toast-icon">${icons[type] || "ℹ️"}</span>
      <span class="toast-message">${escapeHtml(message)}</span>
      <button class="toast-close" type="button" aria-label="Close">✕</button>
    `;
    toast.querySelector(".toast-close").addEventListener("click", () => {
      toast.classList.add("toast-fade-out");
      setTimeout(() => toast.remove(), 250);
    });
    container.appendChild(toast);
    setTimeout(() => {
      if (toast.parentNode) {
        toast.classList.add("toast-fade-out");
        setTimeout(() => toast.remove(), 250);
      }
    }, duration);
  }

  // 9. Empty State Helper
  function renderEmptyState(container, { icon = "🛡️", title = "No data available", subtitle = "", actionText = null, onAction = null }) {
    if (!container) return;
    container.innerHTML = `
      <div class="satya-empty-state">
        <div class="empty-state-icon">${icon}</div>
        <h4 class="empty-state-title">${escapeHtml(title)}</h4>
        ${subtitle ? `<p class="empty-state-subtitle">${escapeHtml(subtitle)}</p>` : ''}
        ${actionText && typeof onAction === "function" ? `
          <button type="button" class="empty-state-btn">${escapeHtml(actionText)}</button>
        ` : ''}
      </div>
    `;
    if (actionText && typeof onAction === "function") {
      container.querySelector(".empty-state-btn")?.addEventListener("click", onAction);
    }
  }

  // 10. Threat Badge Helper
  function renderThreatBadge(level = "LOW") {
    const l = (level || "LOW").toUpperCase();
    let badgeClass = "badge-low";
    if (l === "MEDIUM" || l === "MODERATE") badgeClass = "badge-medium";
    else if (l === "HIGH") badgeClass = "badge-high";
    else if (l === "CRITICAL") badgeClass = "badge-critical";
    return `<span class="threat-badge ${badgeClass}">${escapeHtml(l)}</span>`;
  }

  return {
    renderModeToggle,
    renderScamDigitalDNA,
    renderAttackIntent,
    renderAttackFlow,
    renderMultimodalEvidence,
    renderRecommendedActions,
    renderFraudCopilot,
    showToast,
    renderEmptyState,
    renderThreatBadge,
    escapeHtml,
  };
})();

if (typeof window !== "undefined") {
  window.SatyaComponents = SatyaComponents;
}

