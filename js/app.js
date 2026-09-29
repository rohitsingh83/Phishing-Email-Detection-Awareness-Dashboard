/**
 * Main Application Controller
 * Handles email forensics, sample preset loaders, file uploads,
 * live results rendering, and audit history management.
 */

// Sample Email Presets for 1-Click Verification & Demos
const SAMPLES = {
  legit: {
    sender: "pm-office@brightline.example.net",
    subject: "Quarterly All-Hands Meeting Schedule - Q3 2026",
    body: "Hi Team,\n\nPlease find the schedule for our upcoming quarterly all-hands meeting on Friday at 2:00 PM EST.\nWe will review department accomplishments and Q4 milestones.\n\nAgenda:\n1. Executive Summary\n2. Engineering Highlights\n3. Q&A Session\n\nYou can review the slide deck on our internal knowledge base: https://portal.brightline.example.net/meetings/all-hands\n\nBest regards,\nInternal Communications Team",
    urls: "https://portal.brightline.example.net/meetings/all-hands",
    attachment: "All_Hands_Agenda.pdf"
  },
  phish_urgent: {
    sender: "security-alert@account-verify.invalid.test",
    subject: "URGENT: Immediate Account Verification Required Within 24 Hours",
    body: "Dear Valued Customer / Account Holder,\n\nWe detected suspicious and unauthorized login attempts to your account from an unknown IP address.\nTo protect your funds and personal information, your account access has been temporarily restricted.\n\nACT NOW: You must verify your credentials immediately to avoid permanent account termination.\nFailure to confirm your password and identity within 24 hours will result in permanent suspension.\n\nClick below to verify your account right now:\nhttp://198.51.100.10/verify-account-login\n\nDo not ignore this warning.\n\nSecurity Department",
    urls: "http://198.51.100.10/verify-account-login",
    attachment: ""
  },
  phish_invoice: {
    sender: "billing-support@invoicing-desk.invalid.test",
    subject: "OVERDUE INVOICE #894210: Immediate Payment Required to Avoid Legal Action",
    body: "Attn: Accounts Payable / Account Owner,\n\nOur records indicate an outstanding balance of $3,840.00 on Invoice #894210 which is now severely past due.\nUnless immediate payment is processed today, your account will be turned over to our third-party debt collection agency and legal action will commence.\n\nPlease review the attached invoice statement and remittance voucher immediately:\nDownload invoice: http://invoicing-desk.invalid.test/pay-now-portal?ref=894210\n\nPlease find the attached breakdown invoice document.\n\nAccounting Department",
    urls: "http://invoicing-desk.invalid.test/pay-now-portal?ref=894210",
    attachment: "Invoice_Overdue_894210.pdf.exe"
  }
};

document.addEventListener("DOMContentLoaded", () => {
  // UI Element Bindings
  const senderInput = document.getElementById("sender-input");
  const subjectInput = document.getElementById("subject-input");
  const bodyInput = document.getElementById("body-input");
  const urlsInput = document.getElementById("urls-input");
  const attachmentInput = document.getElementById("attachment-input");

  const btnAnalyze = document.getElementById("btn-analyze");
  const btnClear = document.getElementById("btn-clear");
  const fileUpload = document.getElementById("file-upload");

  const historyTableBody = document.getElementById("history-table-body");
  const historySearch = document.getElementById("history-search");
  const historyFilter = document.getElementById("history-filter");

  // Sample Preset Buttons
  document.getElementById("load-sample-legit")?.addEventListener("click", () => populateForm(SAMPLES.legit));
  document.getElementById("load-sample-phish-urgent")?.addEventListener("click", () => populateForm(SAMPLES.phish_urgent));
  document.getElementById("load-sample-phish-invoice")?.addEventListener("click", () => populateForm(SAMPLES.phish_invoice));

  function populateForm(sample) {
    senderInput.value = sample.sender;
    subjectInput.value = sample.subject;
    bodyInput.value = sample.body;
    urlsInput.value = sample.urls;
    attachmentInput.value = sample.attachment;
  }

  // Clear Form
  btnClear?.addEventListener("click", () => {
    senderInput.value = "";
    subjectInput.value = "";
    bodyInput.value = "";
    urlsInput.value = "";
    attachmentInput.value = "";
    document.getElementById("results-placeholder").classList.remove("hidden");
    document.getElementById("results-display").classList.add("hidden");
  });

  // Analyze Click
  btnAnalyze?.addEventListener("click", async () => {
    const sender = senderInput.value.trim();
    const subject = subjectInput.value.trim();
    const body = bodyInput.value.trim();
    const urls = urlsInput.value.trim();
    const attachment = attachmentInput.value.trim();

    if (!sender && !subject && !body) {
      alert("Please provide email details (Sender, Subject, or Body) before initiating analysis.");
      return;
    }

    btnAnalyze.disabled = true;
    btnAnalyze.innerText = "Analyzing Forensics...";

    try {
      const res = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          sender: sender || "unknown@sample.test",
          subject: subject || "(No Subject)",
          body: body || "",
          urls: urls,
          attachment_name: attachment
        })
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Analysis request failed.");
      }

      const result = await res.json();
      renderAnalysisResults(result);

      // Refresh Dashboard & History
      if (typeof fetchAndUpdateDashboard === "function") fetchAndUpdateDashboard();
      loadHistory();

    } catch (err) {
      alert("Error: " + err.message);
    } finally {
      btnAnalyze.disabled = false;
      btnAnalyze.innerHTML = `
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/>
        </svg> Analyze Email
      `;
    }
  });

  // File Upload Handling
  fileUpload?.addEventListener("change", async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    const formData = new FormData();
    formData.append("file", file);

    try {
      btnAnalyze.disabled = true;
      btnAnalyze.innerText = "Parsing Sample File...";

      const res = await fetch("/api/analyze/file", {
        method: "POST",
        body: formData
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "File analysis failed.");
      }

      const result = await res.json();
      // Populate inputs with parsed content
      if (result.parsed_metadata) {
        senderInput.value = result.parsed_metadata.sender || "";
        subjectInput.value = result.parsed_metadata.subject || "";
        attachmentInput.value = result.parsed_metadata.attachment_name || "";
      }

      renderAnalysisResults(result);
      if (typeof fetchAndUpdateDashboard === "function") fetchAndUpdateDashboard();
      loadHistory();

    } catch (err) {
      alert("File Upload Error: " + err.message);
    } finally {
      btnAnalyze.disabled = false;
      btnAnalyze.innerHTML = `
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/>
        </svg> Analyze Email
      `;
      fileUpload.value = "";
    }
  });

  // Render Forensic Analysis Results in Live Panel
  function renderAnalysisResults(data) {
    const placeholder = document.getElementById("results-placeholder");
    const display = document.getElementById("results-display");
    placeholder.classList.add("hidden");
    display.classList.remove("hidden");

    const score = data.hybrid_risk_score;
    const dial = document.querySelector(".score-dial");
    const badge = document.getElementById("res-classification");
    const number = document.getElementById("res-score");
    const summary = document.getElementById("res-summary");

    number.innerText = score;
    badge.innerText = data.classification;

    // Reset Badge & Dial styling
    badge.className = "classification-badge";
    if (score >= 71) {
      dial.style.borderColor = "var(--accent-red)";
      badge.classList.add("badge-high");
      summary.innerText = "🚨 High threat probability. Multi-vector social-engineering or malicious IOCs detected.";
    } else if (score >= 41) {
      dial.style.borderColor = "var(--accent-amber)";
      badge.classList.add("badge-suspicious");
      summary.innerText = "⚠️ Elevated suspicion. Contains deceptive patterns or non-standard URLs.";
    } else if (score >= 21) {
      dial.style.borderColor = "#eab308";
      badge.classList.add("badge-moderate");
      summary.innerText = "🔍 Moderate indicators detected. Exercise cautious verification.";
    } else {
      dial.style.borderColor = "var(--accent-green)";
      badge.classList.add("badge-low");
      summary.innerText = "✅ Low risk profile. Conforms to standard professional communications.";
    }

    // Scores Chips
    document.getElementById("res-rule-score").innerText = data.rule_engine?.score || 0;
    document.getElementById("res-ml-score").innerText = `${data.machine_learning?.ml_score || 0}%`;
    document.getElementById("res-ml-label").innerText = data.machine_learning?.ml_label || "N/A";

    // Indicators ("WHY?")
    const indicatorsList = document.getElementById("res-indicators");
    indicatorsList.innerHTML = "";
    const indicators = data.indicators || [];

    if (indicators.length === 0) {
      indicatorsList.innerHTML = `<li class="indicator-item sev-low">
        <span class="ind-icon">✅</span>
        <div>
          <div class="ind-title">No High-Risk Behavioral Triggers Detected</div>
          <div class="ind-desc">Message body and header patterns appear standard and non-coercive.</div>
        </div>
      </li>`;
    } else {
      indicators.forEach(ind => {
        const sevClass = ind.severity === "CRITICAL" ? "sev-critical" :
                         ind.severity === "HIGH" ? "sev-high" :
                         ind.severity === "MEDIUM" ? "sev-medium" : "sev-low";
        const icon = ind.severity === "CRITICAL" || ind.severity === "HIGH" ? "🚨" :
                     ind.severity === "MEDIUM" ? "⚠️" : "ℹ️";

        const li = document.createElement("li");
        li.className = `indicator-item ${sevClass}`;
        li.innerHTML = `
          <span class="ind-icon">${icon}</span>
          <div>
            <div class="ind-title">[${ind.category}] ${ind.title} (${ind.severity})</div>
            <div class="ind-desc">${ind.description}</div>
          </div>
        `;
        indicatorsList.appendChild(li);
      });
    }

    // Sender Details Drawer
    const senderDetails = document.getElementById("res-sender-details");
    const sender = data.sender_analysis || {};
    document.getElementById("tag-sender-risk").innerText = `Risk: ${sender.sender_risk_score || 0}/100`;
    senderDetails.innerHTML = `
      <div><strong>Domain:</strong> ${sender.domain || "N/A"}</div>
      <div><strong>Display Name:</strong> ${sender.display_name || "(None)"}</div>
      <div><strong>Subdomains Count:</strong> ${sender.subdomain_count || 0}</div>
      <div style="margin-top:0.4rem;"><strong>Findings:</strong></div>
      <ul>${(sender.findings || []).map(f => `<li>[${f.severity}] ${f.description}</li>`).join("") || "<li>No anomalous domain signals.</li>"}</ul>
    `;

    // URL Details Drawer
    const urlDetails = document.getElementById("res-url-details");
    const urls = data.url_analysis || {};
    document.getElementById("tag-url-risk").innerText = `${urls.total_urls || 0} URL(s) - Risk: ${urls.aggregated_risk_score || 0}/100`;
    if (!urls.url_details || urls.url_details.length === 0) {
      urlDetails.innerHTML = "<div>No hyperlinks extracted from email message.</div>";
    } else {
      urlDetails.innerHTML = urls.url_details.map(u => `
        <div style="margin-bottom:0.6rem; padding-bottom:0.4rem; border-bottom:1px dashed #243452;">
          <div><strong>Target:</strong> <code style="color:#38bdf8;">${u.url}</code></div>
          <div><strong>Scheme:</strong> ${u.scheme} | <strong>Raw IP:</strong> ${u.is_raw_ip ? 'YES (High Risk)' : 'No'} | <strong>Risk:</strong> ${u.risk_score}/100</div>
          <div><strong>Findings:</strong> ${u.findings.map(f => `[${f.severity}] ${f.description}`).join("; ") || "Standard domain pattern."}</div>
        </div>
      `).join("");
    }

    // Attachment Details Drawer
    const attDetails = document.getElementById("res-att-details");
    const att = data.attachment_analysis || {};
    document.getElementById("tag-att-risk").innerText = att.has_attachment ? `${att.filename} (${att.severity})` : "None";
    if (!att.has_attachment) {
      attDetails.innerHTML = "<div>No attachment declared or found in message metadata.</div>";
    } else {
      attDetails.innerHTML = `
        <div><strong>Filename:</strong> ${att.filename}</div>
        <div><strong>Extension:</strong> ${att.primary_extension || "None"}</div>
        <div><strong>Double Extension Masquerade:</strong> ${att.is_double_extension ? 'CRITICAL DETECTED' : 'No'}</div>
        <div><strong>Attachment Risk Score:</strong> ${att.risk_score}/100</div>
        <div><strong>Forensics:</strong> ${(att.findings || []).map(f => f.description).join("; ") || "Standard document format."}</div>
      `;
    }

    // Recommendations Playbook
    const recList = document.getElementById("res-recommendations");
    recList.innerHTML = (data.recommendations || []).map(r => `<li>${r}</li>`).join("");
  }

  // Load and Render Analysis History
  async function loadHistory() {
    try {
      const q = historySearch?.value.trim() || "";
      const filter = historyFilter?.value || "";
      let url = `/api/analyses?sort_by=created_at&order=DESC&limit=25`;
      if (q) url += `&search=${encodeURIComponent(q)}`;
      if (filter) url += `&classification=${encodeURIComponent(filter)}`;

      const res = await fetch(url);
      if (!res.ok) return;
      const data = await res.json();
      renderHistoryTable(data.analyses || []);
    } catch (err) {
      console.error("Failed to load analysis history:", err);
    }
  }

  function renderHistoryTable(records) {
    if (!historyTableBody) return;
    if (records.length === 0) {
      historyTableBody.innerHTML = `<tr><td colspan="7" class="text-center" style="padding:1.5rem; color:#9ca3af;">No analysis records match current filter.</td></tr>`;
      return;
    }

    historyTableBody.innerHTML = records.map(r => {
      const pillClass = r.risk_score >= 71 ? "pill-high" :
                        r.risk_score >= 41 ? "pill-suspicious" : "pill-low";
      const displayDate = r.created_at ? r.created_at.replace("T", " ").substring(0, 16) : "Just now";

      return `
        <tr>
          <td>#${r.analysis_id}</td>
          <td>${displayDate}</td>
          <td><code>${r.sender_domain || 'unknown'}</code></td>
          <td style="max-width:240px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${r.subject}</td>
          <td><span class="score-pill ${pillClass}">${r.risk_score}/100</span></td>
          <td><span class="tag">${r.classification}</span></td>
          <td>
            <button class="btn-icon" title="View Forensics" onclick="viewHistoryDetail(${r.analysis_id})">🔍</button>
            <button class="btn-icon" title="Delete Entry" onclick="deleteHistoryRecord(${r.analysis_id})">🗑️</button>
          </td>
        </tr>
      `;
    }).join("");
  }

  // Filter and Search Listeners
  historySearch?.addEventListener("input", debounce(loadHistory, 300));
  historyFilter?.addEventListener("change", loadHistory);

  // Helper debounce
  function debounce(func, wait) {
    let timeout;
    return (...args) => {
      clearTimeout(timeout);
      timeout = setTimeout(() => func.apply(this, args), wait);
    };
  }

  // Global functions for inline table onclicks
  window.viewHistoryDetail = async (id) => {
    try {
      const res = await fetch(`/api/analyses/${id}`);
      if (!res.ok) throw new Error("Could not fetch detail.");
      const item = await res.json();

      const modal = document.getElementById("detail-modal");
      const modalBody = document.getElementById("modal-body");
      document.getElementById("modal-title").innerText = `Analysis Record #${item.analysis_id} - ${item.classification}`;

      modalBody.innerHTML = `
        <div style="margin-bottom:1rem;">
          <p><strong>Subject:</strong> ${item.subject}</p>
          <p><strong>Sender Domain:</strong> <code>${item.sender_domain}</code></p>
          <p><strong>Recorded Timestamp:</strong> ${item.created_at}</p>
          <p><strong>Combined Threat Score:</strong> <span class="score-pill pill-high">${item.risk_score}/100</span></p>
        </div>
        <h4 style="margin-bottom:0.5rem; color:#f3f4f6;">Extracted Indicators:</h4>
        <ul style="margin-left:1.25rem; margin-bottom:1rem;">
          ${(item.indicators || []).map(i => `<li><strong>[${i.category} - ${i.severity}]</strong> ${i.title}: ${i.description}</li>`).join("") || "<li>None recorded.</li>"}
        </ul>
        <h4 style="margin-bottom:0.5rem; color:#f3f4f6;">Analyzed URLs:</h4>
        <ul style="margin-left:1.25rem;">
          ${(item.urls || []).map(u => `<li><code>${u.url_safe_representation}</code> (Risk: ${u.risk_score}/100)</li>`).join("") || "<li>No URLs present.</li>"}
        </ul>
      `;

      modal.classList.remove("hidden");
    } catch (e) {
      alert("Error: " + e.message);
    }
  };

  window.deleteHistoryRecord = async (id) => {
    if (!confirm(`Are you sure you want to delete analysis record #${id}?`)) return;
    try {
      const res = await fetch(`/api/analyses/${id}`, { method: "DELETE" });
      if (res.ok) {
        loadHistory();
        if (typeof fetchAndUpdateDashboard === "function") fetchAndUpdateDashboard();
      }
    } catch (e) {
      alert("Delete failed: " + e.message);
    }
  };

  // Modal Close
  document.getElementById("modal-close")?.addEventListener("click", () => {
    document.getElementById("detail-modal").classList.add("hidden");
  });
  document.getElementById("modal-overlay")?.addEventListener("click", () => {
    document.getElementById("detail-modal").classList.add("hidden");
  });

  // Initial load
  loadHistory();
});
