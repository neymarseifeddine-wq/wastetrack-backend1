/**
 * WasteTrack – API Integration Layer
 * Load this BEFORE wm.js in wm.html
 */

// Automatically use the deployed backend URL in production,
// or localhost when running on your own machine.
const API_BASE = window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1"
    ? "http://localhost:5000/api"
    : "https://YOUR-APP-NAME.up.railway.app/api";  // ← replace with your Railway URL after deploying

// ─────────────────────────────────────────────
// 1. Token Store  (localStorage so it survives refresh)
// ─────────────────────────────────────────────
const TokenStore = {
    set(access, refresh) {
        localStorage.setItem("wt_access",  access);
        localStorage.setItem("wt_refresh", refresh);
    },
    getAccess()  { return localStorage.getItem("wt_access");  },
    getRefresh() { return localStorage.getItem("wt_refresh"); },
    clear() {
        localStorage.removeItem("wt_access");
        localStorage.removeItem("wt_refresh");
        // Also clear legacy session key
        localStorage.removeItem("wastetrack_user");
    }
};

// ─────────────────────────────────────────────
// 2. Authenticated fetch (auto-refreshes on 401)
// ─────────────────────────────────────────────
async function apiFetch(path, options = {}) {
    // FIX: Don't set Content-Type for FormData — the browser sets it automatically
    // with the correct multipart boundary. Forcing JSON here would break file uploads.
    const isFormData = options.body instanceof FormData;
    const headers = isFormData
        ? { ...(options.headers || {}) }
        : { "Content-Type": "application/json", ...(options.headers || {}) };

    const token = TokenStore.getAccess();
    if (token) headers["Authorization"] = `Bearer ${token}`;

    let res = await fetch(`${API_BASE}${path}`, { ...options, headers });

    if (res.status === 401 && TokenStore.getRefresh()) {
        const rr = await fetch(`${API_BASE}/auth/refresh`, {
            method: "POST",
            headers: { "Authorization": `Bearer ${TokenStore.getRefresh()}` }
        });
        if (rr.ok) {
            const { access_token } = await rr.json();
            TokenStore.set(access_token, TokenStore.getRefresh());
            headers["Authorization"] = `Bearer ${access_token}`;
            res = await fetch(`${API_BASE}${path}`, { ...options, headers });
        } else {
            TokenStore.clear();
            return null;
        }
    }
    return res;
}

// ─────────────────────────────────────────────
// 3. OAuth redirect catcher
// ─────────────────────────────────────────────
// FIX: Tokens are now passed in the URL hash fragment (e.g. #name/role/access/refresh)
// instead of query params, so they never appear in server logs or Referer headers.
function catchOAuthRedirect() {
    const hash = window.location.hash.slice(1); // remove leading #
    if (!hash) return;

    const parts  = hash.split("/");
    if (parts.length < 4) return;

    const name    = decodeURIComponent(parts[0]);
    const role    = parts[1];
    const access  = parts[2];
    const refresh = parts[3];

    if (access && refresh) {
        TokenStore.set(access, refresh);
        currentUser = name || "User";
        currentRole = role || "citizen";
        updateAuthUI();
        // Clean the hash from the URL without triggering a reload
        window.history.replaceState({}, document.title, window.location.pathname);
        if (currentRole === "admin") {
            setTimeout(() => { showPage("adminReports"); loadAdminComplaints(); }, 150);
        } else {
            showPage("landing");
        }
    }
}

// ─────────────────────────────────────────────
// 4. Session restore
// ─────────────────────────────────────────────
async function checkExistingSession() {
    if (!TokenStore.getAccess()) return;
    try {
        const res = await apiFetch("/auth/me");
        if (res && res.ok) {
            const user  = await res.json();
            currentUser = user.role === "admin" && user.municipality
                ? `${user.name} (${user.municipality})` : user.name;
            currentRole = user.role;
            // Re-render the current page so nav + CTA update correctly
            updateAuthUI();
            // If admin, go to dashboard; otherwise stay on landing with updated UI
            if (currentRole === "admin") {
                showPage("adminReports");
                loadAdminComplaints();
            }
            // For citizens: updateAuthUI() already updated the CTA + nav in-place
        } else {
            TokenStore.clear();
        }
    } catch { TokenStore.clear(); }
}

// ─────────────────────────────────────────────
// 5. Login
// ─────────────────────────────────────────────
async function apiLogin() {
    const email    = (document.getElementById("loginEmail")    || {}).value?.trim()  || "";
    const password = (document.getElementById("loginPassword") || {}).value          || "";

    if (!email || !password) { alert("Please enter your email and password."); return; }

    try {
        const res  = await fetch(`${API_BASE}/auth/login`, {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email, password })
        });
        const data = await res.json();
        if (!res.ok) { alert(data.error || "Login failed"); return; }

        TokenStore.set(data.access_token, data.refresh_token);
        currentUser = data.user.role === "admin" && data.user.municipality
            ? `${data.user.name} (${data.user.municipality})` : data.user.name;
        currentRole = data.user.role;
        updateAuthUI();

        if (currentRole === "admin") {
            showPage("adminReports");
            loadAdminComplaints();
        } else {
            showPage("landing");
        }
    } catch {
        alert("Cannot connect to server. Is app.py running on port 5000?");
    }
}

// ─────────────────────────────────────────────
// 6. Logout
// ─────────────────────────────────────────────
async function logout() {
    try { await apiFetch("/auth/logout", { method: "POST" }); } catch {}
    TokenStore.clear();
    currentUser = null;
    currentRole = null;
    updateAuthUI();
    showPage("landing");
}

// ─────────────────────────────────────────────
// 7. OTP Modal
// ─────────────────────────────────────────────
let _otpPendingEmail    = null;
let _otpPendingCallback = null;

function openOTPModal(email, onSuccess) {
    // Always reset fully — prevents stale email/code from a previous attempt
    _otpPendingEmail    = email;
    _otpPendingCallback = onSuccess;
    const input = document.getElementById("otpInput");
    const error = document.getElementById("otpError");
    const label = document.getElementById("otpEmailLabel");
    if (input) { input.value = ""; }
    if (error) { error.textContent = ""; error.style.color = ""; }
    if (label) label.textContent = `We sent a 6-digit code to ${email}`;
    const modal = document.getElementById("otpModal");
    if (modal) { modal.style.display = "flex"; if (input) setTimeout(() => input.focus(), 100); }
}

function closeOTPModal() {
    const modal = document.getElementById("otpModal");
    if (modal) modal.style.display = "none";
    _otpPendingEmail    = null;
    _otpPendingCallback = null;
}

async function submitOTP() {
    const code    = (document.getElementById("otpInput")  || {}).value?.trim() || "";
    const errorEl = document.getElementById("otpError");
    if (errorEl) errorEl.textContent = "";

    if (code.length !== 6) {
        if (errorEl) errorEl.textContent = "Please enter the 6-digit code.";
        return;
    }

    try {
        const res  = await fetch(`${API_BASE}/auth/verify-code`, {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email: _otpPendingEmail, code })
        });
        const data = await res.json();
        if (!res.ok) {
            if (errorEl) errorEl.textContent = data.error || "Invalid code.";
            return;
        }
        const cb = _otpPendingCallback;
        closeOTPModal();
        if (cb) cb();
    } catch {
        if (errorEl) errorEl.textContent = "Cannot connect to server.";
    }
}

async function resendOTP() {
    if (!_otpPendingEmail) return;
    try {
        const res  = await fetch(`${API_BASE}/auth/send-code`, {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email: _otpPendingEmail })
        });
        const data = await res.json();
        const errorEl = document.getElementById("otpError");
        if (res.ok) {
            if (errorEl) {
                errorEl.style.color = "var(--success,#52b788)";
                errorEl.textContent = "New code sent!";
                setTimeout(() => { errorEl.textContent = ""; errorEl.style.color = ""; }, 3000);
            }
        } else {
            if (errorEl) errorEl.textContent = data.error || "Failed to resend.";
        }
    } catch {
        const errorEl = document.getElementById("otpError");
        if (errorEl) errorEl.textContent = "Cannot connect to server.";
    }
}

// ─────────────────────────────────────────────
// 8. Sign-up with OTP flow
// ─────────────────────────────────────────────
async function apiSignUpCitizen() {
    const name     = (document.getElementById("citizenName")     || {}).value?.trim()  || "";
    const email    = (document.getElementById("citizenEmail")    || {}).value?.trim()  || "";
    const password = (document.getElementById("citizenPassword") || {}).value          || "";
    const terms    = (document.getElementById("citizenTerms")    || {}).checked        || false;

    if (!name || !email || !password || !terms) {
        alert("Please fill in all required fields and agree to the terms.");
        return;
    }
    if (password.length < 6) { alert("Password must be at least 6 characters."); return; }

    let sendData;
    try {
        const res  = await fetch(`${API_BASE}/auth/send-code`, {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email })
        });
        sendData = await res.json();
        if (!res.ok && !sendData.dev_code) { alert(sendData.error || "Failed to send verification code."); return; }
        if (sendData.dev_code) {
            alert(`⚠️ Email not sent (SMTP issue). Dev code: ${sendData.dev_code}\nAlso check your Flask console.`);
        }
    } catch { alert("Cannot connect to server. Is app.py running?"); return; }

    openOTPModal(email, async () => {
        try {
            const res  = await fetch(`${API_BASE}/auth/register`, {
                method: "POST", headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ name, email, password, role: "citizen" })
            });
            const data = await res.json();
            if (!res.ok) { alert(data.error || "Registration failed"); return; }
            TokenStore.set(data.access_token, data.refresh_token);
            currentUser = data.user.name;
            currentRole = data.user.role;
            updateAuthUI();
            alert(`Welcome to WasteTrack, ${data.user.name}! 🌿`);
            showPage("landing");
        } catch { alert("Cannot connect to server."); }
    });
    // Pre-fill OTP if dev_code was returned (SMTP unavailable)
    if (sendData && sendData.dev_code) {
        setTimeout(() => { const inp = document.getElementById("otpInput"); if (inp) inp.value = sendData.dev_code; }, 200);
    }
}

async function apiSignUpAdmin() {
    const adminName      = (document.getElementById("adminName")        || {}).value?.trim()  || "";
    const email          = (document.getElementById("adminEmail")       || {}).value?.trim()  || "";
    const password       = (document.getElementById("adminPassword")    || {}).value          || "";
    const municipality   = (document.getElementById("municipalityName") || {}).value?.trim()  || "";
    const municipalityId = (document.getElementById("municipalityId")   || {}).value?.trim()  || "";
    const terms          = (document.getElementById("adminTerms")       || {}).checked        || false;

    if (!adminName || !email || !password || !municipality || !municipalityId || !terms) {
        alert("Please fill in all required fields and agree to the terms.");
        return;
    }

    let sendData;
    try {
        const res  = await fetch(`${API_BASE}/auth/send-code`, {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email })
        });
        sendData = await res.json();
        if (!res.ok && !sendData.dev_code) { alert(sendData.error || "Failed to send verification code."); return; }
        if (sendData.dev_code) {
            alert(`⚠️ Email not sent (SMTP issue). Dev code: ${sendData.dev_code}\nAlso check your Flask console.`);
        }
    } catch { alert("Cannot connect to server. Is app.py running?"); return; }

    openOTPModal(email, async () => {
        try {
            const res  = await fetch(`${API_BASE}/auth/register`, {
                method: "POST", headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ name: adminName, adminName, email, password, municipality, municipalityId, role: "admin" })
            });
            const data = await res.json();
            if (!res.ok) { alert(data.error || "Registration failed"); return; }
            TokenStore.set(data.access_token, data.refresh_token);
            currentUser = `${adminName} (${municipality})`;
            currentRole = data.user.role;
            updateAuthUI();
            alert(`Thank you, ${adminName}!\nYour admin request for ${municipality} will be reviewed within 2–3 business days.`);
            showPage("landing");
        } catch { alert("Cannot connect to server."); }
    });
    // Pre-fill OTP if dev_code was returned (SMTP unavailable)
    if (sendData && sendData.dev_code) {
        setTimeout(() => { const inp = document.getElementById("otpInput"); if (inp) inp.value = sendData.dev_code; }, 200);
    }
}

// ─────────────────────────────────────────────
// 9. Markers
// ─────────────────────────────────────────────
async function loadMarkersFromAPI(typeFilter = "all") {
    const qs  = typeFilter !== "all" ? `?type=${typeFilter}` : "";
    let data  = null;
    try {
        const res = await apiFetch(`/markers${qs}`);
        if (res && res.ok) data = await res.json();
    } catch { /* network error → fall through to sample data */ }

    // Clear existing markers from the map
    markers.forEach(m => m.setMap(null));
    markers     = [];
    infoWindows = [];

    if (data && data.length > 0) {
        // FIX: was guarded by `if (data.length > 0)` which skipped the clear+load
        // when API returned an empty array. Now always clears, then loads what we have.
        data.forEach(loc => addMarker({
            id:          loc.id,
            lat:         parseFloat(loc.lat),
            lng:         parseFloat(loc.lng),
            title:       loc.title,
            address:     loc.address || "",
            type:        loc.type,
            description: loc.description || ""
        }));
    } else {
        // FIX: Fall back to sample locations when API is unavailable or has no data
        console.warn("[WasteTrack] API returned no markers – loading sample data.");
        locations.forEach(loc => addMarker(loc));
    }
}

async function saveNewMarkerAPI() {
    if (currentRole !== "admin") { alert("Only municipality admins can add locations."); return; }

    const type        = (document.getElementById("markerType")        || {}).value               || "";
    const lat         = parseFloat((document.getElementById("markerLat") || {}).value)            || NaN;
    const lng         = parseFloat((document.getElementById("markerLng") || {}).value)            || NaN;
    const description = (document.getElementById("markerDescription") || {}).value?.trim()        || "";
    const containerId = (document.getElementById("markerContainerId") || {}).value?.trim()        || "";
    const titleInput  = (document.getElementById("markerTitle")       || {}).value?.trim()        || "";
    const typeLabels  = { garbage: "Garbage Container", recycling: "Recycling Container", toxic: "Toxic Material Container" };
    const title       = titleInput || typeLabels[type] || type;
    const address     = containerId ? `ID: ${containerId}` : "New Location";

    if (!type || isNaN(lat) || isNaN(lng) || !description) {
        alert("Please fill in Container Type, coordinates and description.");
        return;
    }

    try {
        const res  = await apiFetch("/markers", {
            method: "POST",
            body:   JSON.stringify({ type, title, lat, lng, description, address })
        });
        const data = await res.json();
        if (!res.ok) { alert(data.error || "Failed to add marker"); return; }

        addMarker({ id: data.id, lat: parseFloat(data.lat), lng: parseFloat(data.lng),
                    title: data.title, address: data.address, type: data.type, description: data.description });

        ["markerLat","markerLng","markerDescription","markerContainerId","markerTitle"].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.value = "";
        });
        const btn = document.getElementById("pickCoordsBtn");
        if (btn) btn.textContent = "📍 Click on map to pick location";
        toggleAddMarker();
        alert("Location has been saved successfully!");
    } catch { alert("Cannot connect to server."); }
}

// ─────────────────────────────────────────────
// 10. Complaints
// ─────────────────────────────────────────────
async function handleComplaintSubmitAPI() {
    const issueType     = (document.getElementById("issueType")    || {}).value             || "";
    const severity      = (document.getElementById("severity")     || {}).value             || "";
    const location      = (document.getElementById("location")     || {}).value?.trim()     || "";
    const description   = (document.getElementById("description")  || {}).value?.trim()     || "";
    const reporterName  = (document.getElementById("reporterName") || {}).value?.trim()     || "";
    const reporterEmail = (document.getElementById("reporterEmail")|| {}).value?.trim()     || "";
    const reporterPhone = (document.getElementById("reporterPhone")|| {}).value?.trim()     || "";
    const followUp      = (document.getElementById("followUp")     || {}).checked           || false;
    const photoFile     = (document.getElementById("photoUpload")  || {}).files?.[0]        || null;

    if (!issueType || !severity || !location || !description || !reporterName || !reporterEmail) {
        alert("Please fill in all required fields");
        return;
    }

    const formData = new FormData();
    formData.append("issueType",     issueType);
    formData.append("severity",      severity);
    formData.append("location",      location);
    formData.append("description",   description);
    formData.append("reporterName",  reporterName);
    formData.append("reporterEmail", reporterEmail);
    formData.append("reporterPhone", reporterPhone);
    formData.append("followUp",      followUp ? "true" : "false");
    if (photoFile) formData.append("photo", photoFile);

    try {
        const res  = await fetch(`${API_BASE}/complaints`, {
            method:  "POST",
            headers: { "Authorization": `Bearer ${TokenStore.getAccess()}` },
            body:    formData
        });
        const data = await res.json();
        if (!res.ok) { alert(data.error || "Submission failed"); return; }

        const successMsg = document.getElementById("successMessage");
        if (successMsg) {
            successMsg.innerHTML = `✅ Report submitted! Reference: <strong>${data.ref_number}</strong>`;
            successMsg.style.display = "block";
            setTimeout(() => {
                if (typeof resetForm === "function") resetForm();
                successMsg.style.display = "none";
            }, 5000);
        }
    } catch { alert("Cannot connect to server."); }
}

// ─────────────────────────────────────────────
// 11. Admin complaints dashboard
// ─────────────────────────────────────────────
async function loadAdminComplaints() {
    const list = document.getElementById("adminReportsList");
    if (!list) return;
    list.innerHTML = '<p style="text-align:center;padding:2rem;color:var(--text-muted,#888);">⏳ Loading reports…</p>';

    try {
        const res = await apiFetch("/complaints");
        if (!res || !res.ok) throw new Error("API error");

        const complaints = await res.json();
        if (!complaints.length) {
            list.innerHTML = '<p style="text-align:center;padding:2rem;color:var(--text-muted,#888)">No reports yet.</p>';
            return;
        }

        allReports = complaints.map(c => ({
            id:          c.ref_number || c.id,
            type:        c.issue_type,
            severity:    c.severity,
            location:    c.location,
            reporter:    c.reporter_name,
            date:        (c.created_at || "").slice(0, 10),
            description: c.description,
            status:      c.status,
            _apiId:      c.id
        }));
        renderAdminReports();
    } catch {
        list.innerHTML = "";
        renderAdminReports(); // fallback to sample data
    }
}

async function resolveReport(id) {
    const report = allReports.find(r => r.id === id);
    if (report && report._apiId) {
        try { await apiFetch(`/complaints/${report._apiId}/status`, { method: "PATCH", body: JSON.stringify({ status: "resolved" }) }); } catch {}
    }
    allReports = allReports.filter(r => r.id !== id);
    renderAdminReports();
}

async function dismissReport(id) {
    const report = allReports.find(r => r.id === id);
    if (report && report._apiId) {
        try { await apiFetch(`/complaints/${report._apiId}/status`, { method: "PATCH", body: JSON.stringify({ status: "closed" }) }); } catch {}
    }
    allReports = allReports.filter(r => r.id !== id);
    renderAdminReports();
}

// ─────────────────────────────────────────────
// 12. Boot
// ─────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", function () {
    catchOAuthRedirect();
    checkExistingSession();
});
