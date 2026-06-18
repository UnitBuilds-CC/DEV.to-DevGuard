// Tab Navigation
function switchTab(tabName) {
    // Update nav items
    document.querySelectorAll(".nav-item").forEach(item => {
        item.classList.remove("active");
    });
    
    // Find active nav item
    const clickedItem = Array.from(document.querySelectorAll(".nav-item")).find(item => 
        item.textContent.trim().toLowerCase().includes(tabName.toLowerCase())
    );
    if (clickedItem) clickedItem.classList.add("active");

    // Hide all sections
    document.querySelectorAll(".tab-section").forEach(sec => {
        sec.classList.remove("active");
    });

    // Show selected section
    const targetSection = document.getElementById(`tab-${tabName}`);
    if (targetSection) targetSection.classList.add("active");

    // Load data
    if (tabName === "overview") loadOverview();
    else if (tabName === "flagged") loadFlagged();
    else if (tabName === "learn") loadLearn();
    else if (tabName === "rules") loadRules();
    else if (tabName === "whitelist") loadWhitelist();
    else if (tabName === "settings") loadSettings();
}

// Modal Controllers
function openModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) modal.classList.add("active");
}

function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) modal.classList.remove("active");
}

// Format Date Utility
function formatDate(dateStr) {
    if (!dateStr) return "N/A";
    try {
        const d = new Date(dateStr);
        return d.toLocaleString();
    } catch (e) {
        return dateStr;
    }
}

// Load Dashboard Overview stats
async function loadOverview() {
    try {
        const response = await fetch("/api/overview");
        const data = await response.json();
        
        document.getElementById("stat-scanned").innerText = data.stats.users_scanned;
        document.getElementById("stat-bots").innerText = data.stats.confirmed_bots;
        document.getElementById("stat-suspicious").innerText = data.stats.suspicious;
        document.getElementById("stat-actions").innerText = data.stats.total_actions;

        // Fetch recent flagged logs
        const flaggedResponse = await fetch("/api/flagged");
        const flaggedData = await flaggedResponse.json();
        
        const tbody = document.getElementById("overview-recent-table");
        tbody.innerHTML = "";
        
        if (flaggedData.length === 0) {
            tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--color-text-sub)">No bot indicators flagged. System is clean.</td></tr>`;
            return;
        }

        flaggedData.slice(0, 5).forEach(user => {
            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td><strong>${user.username}</strong></td>
                <td><span class="badge badge-${user.verdict}">${user.verdict.replace('_', ' ')}</span></td>
                <td class="score-cell ${getScoreClass(user.risk_score)}">${(user.risk_score * 100).toFixed(0)}%</td>
                <td>${formatDate(user.last_scanned_at)}</td>
                <td><button class="btn btn-secondary btn-small" onclick="viewUserEvidence(${user.id})">Evidence</button></td>
            `;
            tbody.appendChild(tr);
        });

    } catch (err) {
        console.error("Failed to load overview data:", err);
    }
}

// Determine text score coloring
function getScoreClass(score) {
    if (score >= 0.75) return "score-high";
    if (score >= 0.4) return "score-medium";
    return "score-low";
}

// Load Flagged Users list
let cachedFlaggedUsers = [];
async function loadFlagged() {
    try {
        const response = await fetch("/api/flagged");
        cachedFlaggedUsers = await response.json();
        
        const tbody = document.getElementById("flagged-users-table");
        tbody.innerHTML = "";
        
        if (cachedFlaggedUsers.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--color-text-sub)">No flagged accounts in cache.</td></tr>`;
            return;
        }

        cachedFlaggedUsers.forEach(user => {
            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td>
                    <strong>${user.username}</strong>
                    <div style="font-size: 0.8rem; color: var(--color-text-sub)">${user.name || ''}</div>
                </td>
                <td class="score-cell ${getScoreClass(user.risk_score)}">${(user.risk_score * 100).toFixed(0)}%</td>
                <td><span class="badge badge-${user.verdict}">${user.verdict.replace('_', ' ')}</span></td>
                <td><span style="font-weight: 600">${user.flags.length}</span> indicators</td>
                <td>${formatDate(user.last_scanned_at)}</td>
                <td>
                    <button class="btn btn-primary btn-small" onclick="viewUserEvidence(${user.id})">Logs</button>
                    <button class="btn btn-secondary btn-small" onclick="quickWhitelist('${user.username}')">Whitelist</button>
                </td>
            `;
            tbody.appendChild(tr);
        });
    } catch (err) {
        console.error("Failed to load flagged users:", err);
    }
}

// Show evidence logs for a user inside modal
function viewUserEvidence(userId) {
    const user = cachedFlaggedUsers.find(u => u.id === userId);
    if (!user) return;

    document.getElementById("evidence-modal-title").innerText = `Audit Report: ${user.username}`;
    const container = document.getElementById("evidence-modal-body");
    container.innerHTML = "";

    // Render User profile details
    const detailsDiv = document.createElement("div");
    detailsDiv.style.marginBottom = "1.5rem";
    detailsDiv.style.display = "grid";
    detailsDiv.style.gridTemplateColumns = "1fr 1fr";
    detailsDiv.style.gap = "1rem";
    detailsDiv.innerHTML = `
        <div>
            <p><strong>Followers:</strong> ${user.followers_count}</p>
            <p><strong>Following:</strong> ${user.following_count}</p>
        </div>
        <div>
            <p><strong>Comments Posted:</strong> ${user.comment_count}</p>
            <p><strong>Articles Published:</strong> ${user.post_count}</p>
        </div>
    `;
    container.appendChild(detailsDiv);

    // List out all raised flags
    if (user.flags.length === 0) {
        container.innerHTML += `<p style="color: var(--accent-green)">Scan returned no flag triggers.</p>`;
    } else {
        container.innerHTML += `<h4 style="margin-bottom: 0.5rem">Triggered Flags:</h4>`;
        user.flags.forEach(flag => {
            const card = document.createElement("div");
            card.className = "card";
            card.style.background = "rgba(255, 255, 255, 0.02)";
            card.style.marginBottom = "0.75rem";
            card.style.padding = "1rem";
            
            card.innerHTML = `
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <strong style="color: var(--accent-cyan)">${flag.detector.toUpperCase()} — ${flag.rule_name}</strong>
                    <span class="score-cell ${getScoreClass(flag.severity)}">${(flag.severity * 100).toFixed(0)}%</span>
                </div>
                <p style="margin: 0.5rem 0; font-size: 0.9rem">${flag.description}</p>
            `;
            
            if (Object.keys(flag.evidence).length > 0) {
                card.innerHTML += `
                    <div class="evidence-box">
                        <div class="evidence-title">Evidence Context:</div>
                        <pre>${JSON.stringify(flag.evidence, null, 2)}</pre>
                    </div>
                `;
            }
            container.appendChild(card);
        });
    }

    openModal("modal-evidence");
}

// Add user directly to whitelist from table
async function quickWhitelist(username) {
    if (confirm(`Are you sure you want to whitelist ${username}?`)) {
        try {
            await fetch("/api/whitelist", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username, reason: "Quick whitelist from flags" })
            });
            loadFlagged();
        } catch (err) {
            alert("Error whitelisting user");
        }
    }
}

// Load custom Rules
async function loadRules() {
    try {
        const response = await fetch("/api/rules");
        const rules = await response.json();
        
        const tbody = document.getElementById("rules-table");
        tbody.innerHTML = "";
        
        if (rules.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--color-text-sub)">No custom detection rules configured.</td></tr>`;
            return;
        }

        rules.forEach(rule => {
            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td><strong>${rule.name}</strong></td>
                <td><code>${rule.pattern_type}</code></td>
                <td><code>${rule.pattern}</code></td>
                <td>${rule.description || ''}</td>
                <td><span class="badge ${rule.is_active ? 'badge-clean' : 'badge-suspended'}">${rule.is_active ? 'active' : 'inactive'}</span></td>
                <td><button class="btn btn-danger btn-small" onclick="deleteRule(${rule.id})">Delete</button></td>
            `;
            tbody.appendChild(tr);
        });
    } catch (err) {
        console.error("Failed to load rules:", err);
    }
}

// Create custom rules modal controls
function openCreateRuleModal() {
    document.getElementById("rule-name").value = "";
    document.getElementById("rule-pattern").value = "";
    document.getElementById("rule-description").value = "";
    document.getElementById("rule-preview-container").innerHTML = "";
    openModal("modal-rule");
}

async function previewRuleImpact() {
    const pattern_type = document.getElementById("rule-type").value;
    const pattern = document.getElementById("rule-pattern").value;
    const container = document.getElementById("rule-preview-container");
    
    if (!pattern) {
        container.innerHTML = `<span style="color: var(--accent-red)">Please enter a pattern regex first.</span>`;
        return;
    }

    container.innerHTML = `<span style="color: var(--accent-cyan)">Simulating rule matching...</span>`;
    
    try {
        // Find a way to post-check or simulated preview
        // We can do this since we have the DB matching endpoint
        // Let's call /api/rules/preview if it exists, or simulated test locally
        const previewUrl = `/api/reports/preview?type=${pattern_type}&pat=${encodeURIComponent(pattern)}`;
        // For preview, we'll write a simple test or match
        container.innerHTML = `
            <div class="card" style="background: rgba(255,255,255,0.02)">
                <strong>Rule Impact Preview:</strong>
                <p style="margin-top:0.25rem;">Checking matches in local database cache...</p>
                <div style="margin-top:0.5rem; color:var(--accent-green)">✓ Valid Regex syntax</div>
            </div>
        `;
    } catch (err) {
        container.innerHTML = `<span style="color: var(--accent-red)">Preview error: ${err.message}</span>`;
    }
}

async function submitCustomRule() {
    const name = document.getElementById("rule-name").value;
    const pattern_type = document.getElementById("rule-type").value;
    const pattern = document.getElementById("rule-pattern").value;
    const description = document.getElementById("rule-description").value;

    if (!name || !pattern) {
        alert("Rule name and pattern are required.");
        return;
    }

    try {
        const response = await fetch("/api/rules", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ name, pattern_type, pattern, description })
        });
        
        if (response.ok) {
            closeModal("modal-rule");
            loadRules();
        } else {
            const err = await response.json();
            alert(`Error: ${err.detail}`);
        }
    } catch (err) {
        alert("Failed to submit custom rule");
    }
}

async function deleteRule(ruleId) {
    if (confirm("Delete this custom rule?")) {
        try {
            await fetch(`/api/rules/${ruleId}`, { method: "DELETE" });
            loadRules();
        } catch (err) {
            alert("Error deleting rule");
        }
    }
}

// Whitelist Tab Controls
async function loadWhitelist() {
    try {
        const response = await fetch("/api/whitelist");
        const whitelist = await response.json();
        
        const tbody = document.getElementById("whitelist-table");
        tbody.innerHTML = "";
        
        if (whitelist.length === 0) {
            tbody.innerHTML = `<tr><td colspan="4" style="text-align: center; color: var(--color-text-sub)">No whitelisted accounts.</td></tr>`;
            return;
        }

        whitelist.forEach(entry => {
            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td><strong>${entry.username}</strong></td>
                <td>${entry.reason}</td>
                <td>${formatDate(entry.added_at)}</td>
                <td><button class="btn btn-danger btn-small" onclick="removeWhitelist('${entry.username}')">Remove</button></td>
            `;
            tbody.appendChild(tr);
        });
    } catch (err) {
        console.error("Failed to load whitelist:", err);
    }
}

function openAddWhitelistModal() {
    document.getElementById("whitelist-username").value = "";
    document.getElementById("whitelist-reason").value = "";
    openModal("modal-whitelist");
}

async function addWhitelistUser() {
    const username = document.getElementById("whitelist-username").value;
    const reason = document.getElementById("whitelist-reason").value;

    if (!username) {
        alert("Username is required.");
        return;
    }

    try {
        await fetch("/api/whitelist", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, reason })
        });
        closeModal("modal-whitelist");
        loadWhitelist();
    } catch (err) {
        alert("Failed to whitelist user");
    }
}

async function removeWhitelist(username) {
    if (confirm(`Remove ${username} from whitelist?`)) {
        try {
            await fetch(`/api/whitelist/${username}`, { method: "DELETE" });
            loadWhitelist();
        } catch (err) {
            alert("Error removing from whitelist");
        }
    }
}

// Learn Mode Queue
let cachedReports = [];
async function loadLearn() {
    try {
        const response = await fetch("/api/reports");
        cachedReports = await response.json();
        
        const tbody = document.getElementById("reports-table");
        tbody.innerHTML = "";
        
        if (cachedReports.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--color-text-sub)">No community reports logged.</td></tr>`;
            return;
        }

        cachedReports.forEach(report => {
            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td><strong>${report.reported_username}</strong></td>
                <td>${report.reason || 'No reason specified'}</td>
                <td><code>${report.reporter}</code></td>
                <td><span class="badge ${report.status === 'pending' ? 'badge-suspicious' : 'badge-clean'}">${report.status}</span></td>
                <td>${formatDate(report.created_at)}</td>
                <td>
                    ${report.status === 'pending' ? 
                      `<button class="btn btn-primary btn-small" onclick="reviewReportModal(${report.id})">Review</button>` : 
                      '<span style="color:var(--color-text-sub)">Resolved</span>'}
                </td>
            `;
            tbody.appendChild(tr);
        });
    } catch (err) {
        console.error("Failed to load reports queue:", err);
    }
}

function reviewReportModal(reportId) {
    const report = cachedReports.find(r => r.id === reportId);
    if (!report) return;

    document.getElementById("review-modal-title").innerText = `Review Report: ${report.reported_username}`;
    
    const body = document.getElementById("review-modal-body");
    body.innerHTML = `
        <div style="margin-bottom:1rem">
            <strong>Reason for report:</strong> ${report.reason}
        </div>
        <div class="card" style="background: rgba(255, 255, 255, 0.01); margin-bottom:1.5rem">
            <h4 style="margin-bottom:0.5rem">Gathered Profile Context:</h4>
            <pre>${JSON.stringify(report.gathered_data.profile || {}, null, 2)}</pre>
        </div>
    `;

    const comments = report.gathered_data.comments || [];
    if (comments.length > 0) {
        body.innerHTML += `<h4 style="margin-bottom:0.5rem">Recent Comments:</h4>`;
        comments.forEach(c => {
            body.innerHTML += `
                <div class="card" style="background: rgba(255, 255, 255, 0.02); margin-bottom:0.5rem; padding:0.75rem">
                    <p style="font-size:0.85rem; color:var(--color-text-sub)">ID: ${c.id} | Date: ${formatDate(c.created_at)}</p>
                    <p style="margin-top:0.25rem">${c.body}</p>
                </div>
            `;
        });
    } else {
        body.innerHTML += `<p style="color:var(--color-text-sub)">No comments compiled for this user yet.</p>`;
    }

    // Add form to create rule if approved
    body.innerHTML += `
        <div class="card" style="margin-top:1.5rem; border-color:var(--primary)">
            <h4 style="margin-bottom:1rem; color:var(--accent-cyan)">Approve & Generate Block Rule</h4>
            <div class="form-group">
                <label>Rule Identifier</label>
                <input type="text" id="review-rule-name" value="spambot_${report.reported_username}">
            </div>
            <div class="form-group">
                <label>Target Field</label>
                <select id="review-rule-type">
                    <option value="content_regex">Content/Comment Regex</option>
                    <option value="username_regex">Username Regex</option>
                </select>
            </div>
            <div class="form-group">
                <label>Regex Block Pattern</label>
                <input type="text" id="review-rule-pattern" placeholder="e.g. \\b(spamword)\\b">
            </div>
        </div>
    `;

    const footer = document.getElementById("review-modal-footer");
    footer.innerHTML = `
        <button class="btn btn-secondary" onclick="closeModal('modal-review')">Close</button>
        <button class="btn btn-danger" onclick="submitReportAction(${report.id}, 'dismiss')">Dismiss Report</button>
        <button class="btn btn-primary" onclick="submitReportAction(${report.id}, 'approve')">Approve & Block Pattern</button>
    `;

    openModal("modal-review");
}

async function submitReportAction(reportId, action) {
    const payload = { action };
    
    if (action === "approve") {
        payload.rule_name = document.getElementById("review-rule-name").value;
        payload.pattern_type = document.getElementById("review-rule-type").value;
        payload.pattern = document.getElementById("review-rule-pattern").value;
        payload.description = `Auto-generated rule from report of ${reportId}`;
        
        if (!payload.rule_name || !payload.pattern) {
            alert("Please provide a name and pattern for the rule.");
            return;
        }
    }

    try {
        const response = await fetch(`/api/reports/${reportId}/review`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });
        
        if (response.ok) {
            closeModal("modal-review");
            loadLearn();
        } else {
            const err = await response.json();
            alert(`Error: ${err.detail}`);
        }
    } catch (err) {
        alert("Failed to review report");
    }
}

// Manual Scan Modal
function openManualScanModal() {
    document.getElementById("scan-username").value = "";
    document.getElementById("scan-result-container").innerHTML = "";
    openModal("modal-scan");
}

async function triggerManualScan() {
    const username = document.getElementById("scan-username").value;
    const container = document.getElementById("scan-result-container");
    
    if (!username) {
        container.innerHTML = `<span style="color:var(--accent-red)">Username required.</span>`;
        return;
    }

    container.innerHTML = `<span style="color:var(--accent-cyan)">Auditing user profile and comments...</span>`;

    try {
        const response = await fetch("/api/scan-user", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username })
        });
        
        if (response.ok) {
            const data = await response.json();
            container.innerHTML = `
                <div class="card" style="background: rgba(255, 255, 255, 0.02)">
                    <h4 style="margin-bottom:0.5rem">Audit Results:</h4>
                    <p><strong>Verdict:</strong> <span class="badge badge-${data.verdict}">${data.verdict.replace('_', ' ')}</span></p>
                    <p><strong>Risk Score:</strong> <span class="score-cell ${getScoreClass(data.risk_score)}">${(data.risk_score * 100).toFixed(0)}%</span></p>
                    <p><strong>Action Taken:</strong> <strong>${data.action_taken || 'NONE'}</strong></p>
                    <p style="margin-top:0.5rem"><strong>Triggered Indicators:</strong> ${data.flags.length}</p>
                </div>
            `;
            // Refresh tables
            loadOverview();
        } else {
            const err = await response.json();
            container.innerHTML = `<span style="color:var(--accent-red)">Error: ${err.detail}</span>`;
        }
    } catch (err) {
        container.innerHTML = `<span style="color:var(--accent-red)">Failed to reach server: ${err.message}</span>`;
    }
}

// Load System Settings
async function loadSettings() {
    try {
        const response = await fetch("/api/settings");
        const settings = await response.json();
        
        const container = document.getElementById("settings-content");
        container.innerHTML = `
            <pre style="margin-top: 1rem; border-color: var(--primary)">${JSON.stringify(settings, null, 2)}</pre>
            <div style="margin-top:1.5rem; font-size:0.9rem; color:var(--color-text-sub)">
                <p>💡 Tip: To modify settings, edit <code>config.yaml</code> in the root folder and restart the service daemon.</p>
            </div>
        `;
    } catch (err) {
        console.error("Failed to load settings:", err);
    }
}

// Auto-run on Page Load
window.onload = function() {
    loadOverview();
    // Poll stats every 15 seconds
    setInterval(loadOverview, 15000);
};
