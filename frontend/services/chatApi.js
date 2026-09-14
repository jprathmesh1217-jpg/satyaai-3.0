/**
 * SATYA AI 3.0 — Frontend Fraud Copilot Chat API Service
 * Clean integration layer for AI Fraud Investigation Copilot queries.
 */

const ChatAPI = (() => {
  async function sendChatMessage(message, analysisId) {
    if (!message || !message.trim()) {
      throw new Error("Message cannot be empty");
    }

    const payload = {
      message: message.trim(),
      analysis_id: analysisId || (window.AnalysisAPI ? window.AnalysisAPI.getActiveAnalysisId() : null) || null,
    };

    const res = await fetch("/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(err.detail || `Chat query failed (${res.status})`);
    }

    return await res.json();
  }

  async function fetchContext(analysisId) {
    if (!analysisId) return null;
    const res = await fetch(`/api/chat/context/${encodeURIComponent(analysisId)}`);
    if (!res.ok) return null;
    return await res.json();
  }

  return {
    sendChatMessage,
    fetchContext,
  };
})();

if (typeof window !== "undefined") {
  window.ChatAPI = ChatAPI;
}
