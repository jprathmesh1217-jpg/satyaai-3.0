/**
 * SATYA AI 3.0 — Frontend Analysis API Service
 * Clean integration layer for multimodal fraud analysis endpoints.
 */

const AnalysisAPI = (() => {
  let _activeAnalysisId = null;

  function storeAnalysisId(id) {
    if (id) {
      _activeAnalysisId = id;
      sessionStorage.setItem("satya_active_analysis_id", id);
    }
  }

  function getActiveAnalysisId() {
    return _activeAnalysisId || sessionStorage.getItem("satya_active_analysis_id") || null;
  }

  function clearActiveAnalysisId() {
    _activeAnalysisId = null;
    sessionStorage.removeItem("satya_active_analysis_id");
  }

  async function postMessageAnalysis(text) {
    const res = await fetch("/api/analyze/message", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(err.detail || `Analysis failed (${res.status})`);
    }
    const data = await res.json();
    if (data.analysis_id) storeAnalysisId(data.analysis_id);
    return data;
  }

  async function postUrlAnalysis(url) {
    const res = await fetch("/api/analyze/url", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(err.detail || `URL analysis failed (${res.status})`);
    }
    const data = await res.json();
    if (data.analysis_id) storeAnalysisId(data.analysis_id);
    return data;
  }

  async function postFileAnalysis(modality, file) {
    const fd = new FormData();
    fd.append("file", file);
    const res = await fetch(`/api/analyze/${modality}`, {
      method: "POST",
      body: fd,
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(err.detail || `${modality} analysis failed (${res.status})`);
    }
    const data = await res.json();
    if (data.analysis_id) storeAnalysisId(data.analysis_id);
    return data;
  }

  async function postExplanation(payload) {
    const res = await fetch("/api/analyze/explanation", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(err.detail || `Explanation request failed (${res.status})`);
    }
    return await res.json();
  }

  return {
    storeAnalysisId,
    getActiveAnalysisId,
    clearActiveAnalysisId,
    postMessageAnalysis,
    postUrlAnalysis,
    postFileAnalysis,
    postExplanation,
  };
})();

if (typeof window !== "undefined") {
  window.AnalysisAPI = AnalysisAPI;
}
