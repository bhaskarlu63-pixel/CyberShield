import { useState } from "react";
import jsPDF from "jspdf";
import "./App.css";

const API_URL = "/api";

function App() {
  // --------------------------------------------------
  // PAGE
  // --------------------------------------------------

  const [page, setPage] = useState("login");

  // --------------------------------------------------
  // LOGIN / SIGNUP
  // --------------------------------------------------

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");

  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);

  const [message, setMessage] = useState("");
  const [messageType, setMessageType] = useState("");

  const [loggedInUser, setLoggedInUser] = useState("");

  // --------------------------------------------------
  // SCAN
  // --------------------------------------------------

  const [domain, setDomain] = useState("");
  const [scanResult, setScanResult] = useState(null);
  const [scanning, setScanning] = useState(false);

  // --------------------------------------------------
  // REPORTS
  // --------------------------------------------------

  const [reports, setReports] = useState([]);
  const [reportsLoading, setReportsLoading] = useState(false);
  const [selectedReport, setSelectedReport] = useState(null);

  // --------------------------------------------------
  // CREATE ACCOUNT
  // --------------------------------------------------

  const handleSignup = async (e) => {
    e.preventDefault();

    setMessage("");

    if (!username.trim() || !password || !confirmPassword) {
      setMessage("Please fill in all fields.");
      setMessageType("error");
      return;
    }

    if (password !== confirmPassword) {
      setMessage("Passwords do not match.");
      setMessageType("error");
      return;
    }

    try {
      const response = await fetch(`${API_URL}/signup`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          username: username.trim(),
          password: password,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        setMessage(data.detail || "Account creation failed.");
        setMessageType("error");
        return;
      }

      setMessage("Account created successfully! Please login.");
      setMessageType("success");

      setPassword("");
      setConfirmPassword("");
      setShowPassword(false);
      setShowConfirmPassword(false);

      setTimeout(() => {
        setPage("login");
        setMessage("");
      }, 1500);
    } catch (error) {
      setMessage(
        "Cannot connect to CyberShield server. Make sure the backend is running."
      );
      setMessageType("error");
    }
  };

  // --------------------------------------------------
  // LOGIN
  // --------------------------------------------------

  const handleLogin = async (e) => {
    e.preventDefault();

    setMessage("");

    if (!username.trim() || !password) {
      setMessage("Please enter username and password.");
      setMessageType("error");
      return;
    }

    try {
      const response = await fetch(`${API_URL}/login`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          username: username.trim(),
          password: password,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        setMessage(data.detail || "Invalid username or password.");
        setMessageType("error");
        return;
      }

      setLoggedInUser(data.username);

      setMessage("");
      setPassword("");
      setShowPassword(false);

      setPage("dashboard");
    } catch (error) {
      setMessage(
        "Cannot connect to CyberShield server. Make sure the backend is running."
      );
      setMessageType("error");
    }
  };

  // --------------------------------------------------
  // LOGOUT
  // --------------------------------------------------

  const handleLogout = () => {
    setLoggedInUser("");
    setUsername("");
    setPassword("");
    setConfirmPassword("");

    setDomain("");
    setScanResult(null);
    setReports([]);
    setSelectedReport(null);

    setMessage("");
    setShowPassword(false);
    setShowConfirmPassword(false);

    setPage("login");
  };

  // --------------------------------------------------
  // DOMAIN SCAN
  // --------------------------------------------------

  const handleScan = async () => {
    if (!domain.trim()) {
      setMessage("Please enter a domain name.");
      setMessageType("error");
      return;
    }

    setScanning(true);
    setMessage("");
    setScanResult(null);
    setSelectedReport(null);

    try {
      const response = await fetch(
        `${API_URL}/scan?url=${encodeURIComponent(domain.trim())}`
      );

      const data = await response.json();

      if (!response.ok) {
        setMessage(data.detail || "Unable to scan this domain.");
        setMessageType("error");
        setScanning(false);
        return;
      }

      setScanResult(data);

      // Automatically save the report
      await saveReport(data);
    } catch (error) {
      setMessage(
        "Unable to connect to CyberShield server. Make sure the backend is running."
      );
      setMessageType("error");
    }

    setScanning(false);
  };

  // --------------------------------------------------
  // SAVE REPORT
  // --------------------------------------------------

  const saveReport = async (result) => {
    try {
      await fetch(`${API_URL}/reports`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          username: loggedInUser,
          domain: result.domain,
          status_code: result.status_code,
          https_enabled: result.https_enabled,
          protections_detected: result.security_headers_passed,
          protections_total: result.security_headers_total,
          security_score: result.security_score,
          status: result.status,
          findings: result.findings,
        }),
      });
    } catch (error) {
      console.log("Report could not be saved.");
    }
  };

  // --------------------------------------------------
  // GET REPORTS
  // --------------------------------------------------

  const loadReports = async () => {
    setReportsLoading(true);
    setMessage("");

    try {
      const response = await fetch(
        `${API_URL}/reports/${encodeURIComponent(loggedInUser)}`
      );

      const data = await response.json();

      if (!response.ok) {
        setMessage(data.detail || "Unable to load reports.");
        setMessageType("error");
        setReportsLoading(false);
        return;
      }

      setReports(data.reports || []);
      setSelectedReport(null);
      setPage("reports");
    } catch (error) {
      setMessage(
        "Cannot connect to CyberShield server. Make sure the backend is running."
      );
      setMessageType("error");
    }

    setReportsLoading(false);
  };

  // --------------------------------------------------
  // GET ONE REPORT
  // --------------------------------------------------

  const viewReport = async (reportId) => {
    setMessage("");

    try {
      const response = await fetch(`${API_URL}/report/${reportId}`);

      const data = await response.json();

      if (!response.ok) {
        setMessage(data.detail || "Unable to open report.");
        setMessageType("error");
        return;
      }

      setSelectedReport(data);
      setPage("report");
    } catch (error) {
      setMessage(
        "Cannot connect to CyberShield server. Make sure the backend is running."
      );
      setMessageType("error");
    }
  };

  // --------------------------------------------------
  // SECURITY STATUS
  // --------------------------------------------------

  const showSecurityStatus = async () => {
    setMessage("");
    setReportsLoading(true);

    try {
      const response = await fetch(
        `${API_URL}/reports/${encodeURIComponent(loggedInUser)}`
      );

      const data = await response.json();

      if (!response.ok) {
        setMessage(data.detail || "Unable to load security status.");
        setMessageType("error");
        setReportsLoading(false);
        return;
      }

      setReports(data.reports || []);
      setPage("status");
    } catch (error) {
      setMessage(
        "Cannot connect to CyberShield server. Make sure the backend is running."
      );
      setMessageType("error");
    }

    setReportsLoading(false);
  };

  // --------------------------------------------------
  // DOWNLOAD FULL SECURITY REPORT
  // --------------------------------------------------

  const downloadSecurityReport = (result) => {
    if (!result) return;

    const doc = new jsPDF();
    const pageWidth = doc.internal.pageSize.getWidth();
    const pageHeight = doc.internal.pageSize.getHeight();

    let y = 20;

    const addPageIfNeeded = (heightNeeded = 10) => {
      if (y + heightNeeded > pageHeight - 18) {
        doc.addPage();
        y = 20;
      }
    };

    const addText = (text, options = {}) => {
      const {
        size = 11,
        bold = false,
        indent = 0,
        spacing = 6,
      } = options;

      doc.setFont("helvetica", bold ? "bold" : "normal");
      doc.setFontSize(size);

      const lines = doc.splitTextToSize(
        String(text ?? ""),
        pageWidth - 30 - indent
      );

      const lineHeight = size * 0.48 + 2;
      addPageIfNeeded(lines.length * lineHeight + spacing);

      doc.text(lines, 15 + indent, y);
      y += lines.length * lineHeight + spacing;
    };

    const addHeading = (text, size = 14) => {
      addPageIfNeeded(14);
      doc.setFont("helvetica", "bold");
      doc.setFontSize(size);
      doc.text(String(text), 15, y);
      y += size * 0.55 + 5;
    };

    // Title
    doc.setFont("helvetica", "bold");
    doc.setFontSize(20);
    doc.text("CyberShield Security Assessment", 15, y);
    y += 10;

    addText(`Domain: ${result.domain}`, { bold: true });
    addText(`Security Score: ${result.security_score}/100`, { bold: true });
    addText(`Overall Status: ${result.status}`, { bold: true });
    addText(`HTTP Status Code: ${result.status_code}`);
    addText(
      `HTTPS: ${result.https_enabled ? "Enabled" : "Not Detected"}`
    );
    addText(
      `Security Protections: ${result.security_headers_passed}/${result.security_headers_total}`
    );

    addHeading("1. Security Score");
    addText(
      result.security_score >= 80
        ? "Most of the security protections checked by CyberShield were detected."
        : result.security_score >= 50
        ? "Some recommended security protections were detected, but improvements may still be needed."
        : "Several recommended security protections were not detected. Review the findings below."
    );
    addText(
      "This score is based only on the security checks performed by CyberShield. It is not a complete security audit."
    );

    addHeading("2. Connection Security");
    addText(
      result.https_enabled
        ? "HTTPS Enabled"
        : "HTTPS Not Detected",
      { bold: true }
    );
    addText(
      "What does this mean? HTTPS encrypts communication between the user's browser and the website."
    );
    addText(
      "Why is it important? Encryption helps protect information while it travels between the user and the website."
    );

    addHeading("3. Security Protections");
    addText(
      `${result.security_headers_passed}/${result.security_headers_total} security protections detected.`
    );

    addHeading("4. Detailed Security Findings");

    (result.findings || []).forEach((finding, index) => {
      addPageIfNeeded(20);

      addText(
        `${index + 1}. ${finding.passed ? "PROTECTION DETECTED" : "PROTECTION NOT DETECTED"} - ${finding.title}`,
        { size: 12, bold: true, spacing: 5 }
      );

      addText(`Risk Level: ${finding.risk || "Not specified"}`, {
        bold: true,
      });

      addText(`What does this mean? ${finding.what || "Not available."}`);
      addText(`Why is it important? ${finding.why || "Not available."}`);
      addText(
        `How to improve: ${finding.recommendation || "No recommendation provided."}`
      );

      y += 3;
    });

    addHeading("5. Overall Summary");
    addText(
      `CyberShield completed a basic security configuration assessment of ${result.domain}.`
    );
    addText(
      "The scan checks HTTPS and selected security response headers. Missing protections do not automatically mean the website is vulnerable, but they identify areas that may deserve review."
    );

    addHeading("6. Recommended Actions");

    const failedFindings = (result.findings || []).filter(
      (finding) => !finding.passed
    );

    if (failedFindings.length === 0) {
      addText(
        "No missing protections were detected in the checks performed by CyberShield."
      );
    } else {
      failedFindings.forEach((finding, index) => {
        addText(`${index + 1}. ${finding.title}`, {
          bold: true,
          spacing: 3,
        });
        addText(
          finding.recommendation || "Review this security finding.",
          { indent: 5 }
        );
      });
    }

    addHeading("7. Important Note");
    addText(
      "CyberShield provides a basic automated configuration assessment. It should not be treated as a complete penetration test or security audit."
    );

    // Footer on every page
    const pageCount = doc.getNumberOfPages();
    for (let page = 1; page <= pageCount; page++) {
      doc.setPage(page);
      doc.setFont("helvetica", "normal");
      doc.setFontSize(8);
      doc.text(
        `CyberShield Security Assessment - Page ${page} of ${pageCount}`,
        15,
        pageHeight - 8
      );
    }

    const safeDomain = String(result.domain || "website")
      .replace(/^https?:\/\//i, "")
      .replace(/[^a-z0-9.-]/gi, "_")
      .replace(/\.+/g, ".");

    doc.save(`CyberShield_Security_Report_${safeDomain}.pdf`);
  };

  // --------------------------------------------------
  // FINDING CARD
  // --------------------------------------------------

  const FindingCard = ({ finding }) => {
    return (
      <div className={`finding-card ${finding.passed ? "passed" : "warning"}`}>
        <div className="finding-header">
          <div>
            <h3>
              {finding.passed ? "✅" : "⚠️"} {finding.title}
            </h3>

            <span
              className={`risk-badge ${
                finding.risk === "None" ? "risk-none" : "risk-warning"
              }`}
            >
              Risk level: {finding.risk}
            </span>
          </div>

          <strong>
            {finding.passed
              ? "Protection detected"
              : "Protection not detected"}
          </strong>
        </div>

        <div className="finding-section">
          <h4>What does this mean?</h4>
          <p>{finding.what}</p>
        </div>

        <div className="finding-section">
          <h4>Why is it important?</h4>
          <p>{finding.why}</p>
        </div>

        <div className="recommendation">
          <h4>💡 How to improve:</h4>
          <p>{finding.recommendation}</p>
        </div>
      </div>
    );
  };

  // --------------------------------------------------
  // SECURITY REPORT DISPLAY
  // --------------------------------------------------

  const SecurityReport = ({ result }) => {
    if (!result) return null;

    return (
      <div className="security-report">

        <div className="report-title">
          <div className="report-shield">🛡️</div>

          <h1>CyberShield Security Assessment</h1>

          <p className="scanned-domain">
            {result.domain}
          </p>

          <button
            className="download-button"
            onClick={() => downloadSecurityReport(result)}
          >
            📄 Download Full Report
          </button>
        </div>

        {/* SCORE */}

        <div className="score-card">
          <h2>📊 Security Score</h2>

          <div className="score-number">
            {result.security_score}/100
          </div>

          <div
            className={`score-status ${result.status
              .toLowerCase()
              .replace(" ", "-")}`}
          >
            {result.status}
          </div>

          <p>
            {result.security_score >= 80
              ? "Most of the security protections checked by CyberShield were detected."
              : result.security_score >= 50
              ? "Some recommended security protections were detected, but improvements may still be needed."
              : "Several recommended security protections were not detected. Review the findings below."}
          </p>

          <small>
            This score is based only on the security checks performed by
            CyberShield. It is not a complete security audit.
          </small>
        </div>

        {/* BASIC INFORMATION */}

        <div className="info-grid">

          <div className="info-card">
            <h3>🌐 Domain</h3>
            <p>{result.domain}</p>
          </div>

          <div className="info-card">
            <h3>📡 Status Code</h3>
            <p>{result.status_code}</p>
          </div>

          <div className="info-card">
            <h3>🛡️ Protections</h3>
            <p>
              {result.security_headers_passed}/
              {result.security_headers_total}
            </p>
          </div>

        </div>

        {/* CONNECTION SECURITY */}

        <div className="report-section">

          <h2>🔒 Connection Security</h2>

          <div
            className={`connection-box ${
              result.https_enabled ? "secure" : "not-secure"
            }`}
          >
            <h3>
              {result.https_enabled
                ? "✅ HTTPS Enabled"
                : "❌ HTTPS Not Detected"}
            </h3>

            <h4>What does this mean?</h4>

            <p>
              HTTPS encrypts communication between the user's browser
              and the website.
            </p>

            <h4>Why is it important?</h4>

            <p>
              Encryption helps protect information while it travels
              between the user and the website.
            </p>
          </div>

        </div>

        {/* SECURITY PROTECTIONS */}

        <div className="report-section">

          <h2>🛡️ Security Protections</h2>

          <div className="protection-count">
            <strong>
              {result.security_headers_passed}
            </strong>

            <span>/</span>

            <strong>
              {result.security_headers_total}
            </strong>

            <p>protections detected</p>
          </div>

        </div>

        {/* SECURITY FINDINGS */}

        <div className="report-section">

          <h2>🔍 Security Findings</h2>

          {result.findings &&
            result.findings.map((finding, index) => (
              <FindingCard
                key={index}
                finding={finding}
              />
            ))}

        </div>

        {/* OVERALL SUMMARY */}

        <div className="summary-card">

          <h2>📋 Overall Summary</h2>

          <p>
            CyberShield completed a basic security configuration
            assessment of <strong>{result.domain}</strong>.
          </p>

          <p>
            The scan checks HTTPS and selected security response
            headers. Missing protections do not automatically mean
            the website is vulnerable, but they identify areas that
            may deserve review.
          </p>

        </div>

        {/* RECOMMENDED ACTIONS */}

        <div className="actions-card">

          <h2>💡 Recommended Actions</h2>

          {result.findings &&
            result.findings
              .filter((finding) => !finding.passed)
              .map((finding, index) => (
                <div className="action-item" key={index}>
                  <strong>
                    {index + 1}. {finding.title}
                  </strong>

                  <p>
                    {finding.recommendation}
                  </p>
                </div>
              ))}

        </div>

        {/* IMPORTANT */}

        <div className="important-note">

          <strong>ℹ️ Important:</strong>

          <p>
            CyberShield provides a basic automated configuration
            assessment. It should not be treated as a complete
            penetration test or security audit.
          </p>

        </div>

      </div>
    );
  };

  // ==================================================
  // LOGIN / SIGNUP
  // ==================================================

  if (page === "login" || page === "signup") {
    return (
      <div className="app">

        <div className="auth-container">

          <div className="logo">
            <div className="shield-logo">🛡️</div>
            <h1>CyberShield</h1>
          </div>

          {page === "login" ? (
            <>
              <h2>Login</h2>

              <form onSubmit={handleLogin}>

                <input
                  type="text"
                  placeholder="Username"
                  value={username}
                  onChange={(e) =>
                    setUsername(e.target.value)
                  }
                />

                <div className="password-field">

                  <input
                    type={
                      showPassword
                        ? "text"
                        : "password"
                    }
                    placeholder="Password"
                    value={password}
                    onChange={(e) =>
                      setPassword(e.target.value)
                    }
                  />

                  <button
                    type="button"
                    className="eye-button"
                    onClick={() =>
                      setShowPassword(!showPassword)
                    }
                  >
                    {showPassword ? "🙈" : "👁️"}
                  </button>

                </div>

                {message && (
                  <div
                    className={`message ${messageType}`}
                  >
                    {message}
                  </div>
                )}

                <button
                  type="submit"
                  className="main-button"
                >
                  LOGIN
                </button>

              </form>

              <p className="account-text">
                Don't have an account?
              </p>

              <button
                className="secondary-button"
                onClick={() => {
                  setPage("signup");
                  setMessage("");
                  setUsername("");
                  setPassword("");
                  setShowPassword(false);
                }}
              >
                CREATE NEW ACCOUNT
              </button>
            </>
          ) : (
            <>
              <h2>Create New Account</h2>

              <form onSubmit={handleSignup}>

                <input
                  type="text"
                  placeholder="Username"
                  value={username}
                  onChange={(e) =>
                    setUsername(e.target.value)
                  }
                />

                <div className="password-field">

                  <input
                    type={
                      showPassword
                        ? "text"
                        : "password"
                    }
                    placeholder="Password"
                    value={password}
                    onChange={(e) =>
                      setPassword(e.target.value)
                    }
                  />

                  <button
                    type="button"
                    className="eye-button"
                    onClick={() =>
                      setShowPassword(!showPassword)
                    }
                  >
                    {showPassword ? "🙈" : "👁️"}
                  </button>

                </div>

                <div className="password-field">

                  <input
                    type={
                      showConfirmPassword
                        ? "text"
                        : "password"
                    }
                    placeholder="Confirm Password"
                    value={confirmPassword}
                    onChange={(e) =>
                      setConfirmPassword(e.target.value)
                    }
                  />

                  <button
                    type="button"
                    className="eye-button"
                    onClick={() =>
                      setShowConfirmPassword(
                        !showConfirmPassword
                      )
                    }
                  >
                    {showConfirmPassword
                      ? "🙈"
                      : "👁️"}
                  </button>

                </div>

                {message && (
                  <div
                    className={`message ${messageType}`}
                  >
                    {message}
                  </div>
                )}

                <button
                  type="submit"
                  className="main-button"
                >
                  CREATE ACCOUNT
                </button>

              </form>

              <p className="account-text">
                Already have an account?
              </p>

              <button
                className="secondary-button"
                onClick={() => {
                  setPage("login");
                  setMessage("");
                  setConfirmPassword("");
                  setShowPassword(false);
                  setShowConfirmPassword(false);
                }}
              >
                BACK TO LOGIN
              </button>
            </>
          )}

        </div>

      </div>
    );
  }

  // ==================================================
  // DASHBOARD
  // ==================================================

  if (page === "dashboard") {
    return (
      <div className="app">

        <div className="dashboard">

          {/* HEADER */}

          <div className="dashboard-header">

            <div className="brand">
              <div className="shield">🛡️</div>
              <h1>CyberShield</h1>
            </div>

            <button
              className="logout-button"
              onClick={handleLogout}
            >
              Logout
            </button>

          </div>

          {/* WELCOME */}

          <div className="welcome">

            <h2>
              Welcome, {loggedInUser} 👋
            </h2>

            <p>
              Your CyberShield security dashboard is ready.
            </p>

          </div>

          {/* SCAN BOX */}

          <div className="scan-box">

            <h2>🔍 Scan a Website</h2>

            <p>
              Enter a domain name to check its basic security
              configuration.
            </p>

            <div className="scan-input-area">

              <input
                type="text"
                placeholder="example.com"
                value={domain}
                onChange={(e) =>
                  setDomain(e.target.value)
                }
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    handleScan();
                  }
                }}
              />

              <button
                onClick={handleScan}
                disabled={scanning}
              >
                {scanning
                  ? "Scanning..."
                  : "Start Scan"}
              </button>

            </div>

            {message && (
              <div
                className={`message ${messageType}`}
              >
                {message}
              </div>
            )}

          </div>

          {/* DASHBOARD CARDS */}

          <div className="dashboard-cards">

            <div className="dashboard-card">

              <div className="card-icon">
                🌐
              </div>

              <h3>Domain Scan</h3>

              <p>
                Check HTTPS and important security protections
                configured on a website.
              </p>

              <button
                onClick={() =>
                  document
                    .querySelector(".scan-box")
                    ?.scrollIntoView({
                      behavior: "smooth",
                    })
                }
              >
                Start Scan
              </button>

            </div>

            <div className="dashboard-card">

              <div className="card-icon">
                📊
              </div>

              <h3>Security Reports</h3>

              <p>
                View your previous domain security scans and
                detailed findings.
              </p>

              <button onClick={loadReports}>
                {reportsLoading
                  ? "Loading..."
                  : "View Reports"}
              </button>

            </div>

            <div className="dashboard-card">

              <div className="card-icon">
                🛡️
              </div>

              <h3>Security Status</h3>

              <p>
                See the overall security status from your
                previous scans.
              </p>

              <button
                onClick={showSecurityStatus}
              >
                View Status
              </button>

            </div>

          </div>

          {/* INFORMATION */}

          <div className="dashboard-info">

            <h3>CyberShield Protection</h3>

            <p>
              CyberShield helps organizations understand
              cybersecurity risks through simple security
              monitoring, domain scanning and
              easy-to-understand reports.
            </p>

          </div>

          {/* SCAN RESULT */}

          {scanResult && (
            <div className="result-container">

              <button
                className="back-button"
                onClick={() => setScanResult(null)}
              >
                ← Back to Dashboard
              </button>

              <SecurityReport
                result={scanResult}
              />

            </div>
          )}

        </div>

      </div>
    );
  }

  // ==================================================
  // REPORTS PAGE
  // ==================================================

  if (page === "reports") {
    return (
      <div className="app">

        <div className="dashboard">

          <div className="dashboard-header">

            <div className="brand">
              <div className="shield">🛡️</div>
              <h1>CyberShield</h1>
            </div>

            <button
              className="logout-button"
              onClick={handleLogout}
            >
              Logout
            </button>

          </div>

          <div className="page-heading">

            <h2>📊 Security Reports</h2>

            <p>
              Previous security scans performed by {loggedInUser}.
            </p>

          </div>

          <button
            className="back-button"
            onClick={() => setPage("dashboard")}
          >
            ← Back to Dashboard
          </button>

          {reports.length === 0 ? (
            <div className="empty-state">

              <div className="empty-icon">
                📋
              </div>

              <h3>No Reports Yet</h3>

              <p>
                You have not completed any security scans yet.
              </p>

              <button
                className="main-button"
                onClick={() => setPage("dashboard")}
              >
                Scan a Domain
              </button>

            </div>
          ) : (
            <div className="reports-list">

              {reports.map((report) => (
                <div
                  className="report-list-card"
                  key={report.id}
                >

                  <div>
                    <h3>
                      🌐 {report.domain}
                    </h3>

                    <p>
                      Security Score:{" "}
                      <strong>
                        {report.security_score}/100
                      </strong>
                    </p>

                    <p>
                      Protections:{" "}
                      <strong>
                        {report.protections_detected}/
                        {report.protections_total}
                      </strong>
                    </p>

                    <span
                      className={`report-status ${
                        report.status
                          .toLowerCase()
                          .replace(" ", "-")
                      }`}
                    >
                      {report.status}
                    </span>
                  </div>

                  <button
                    className="view-report-button"
                    onClick={() =>
                      viewReport(report.id)
                    }
                  >
                    View Report
                  </button>

                </div>
              ))}

            </div>
          )}

        </div>

      </div>
    );
  }

  // ==================================================
  // SINGLE REPORT PAGE
  // ==================================================

  if (page === "report") {
    return (
      <div className="app">

        <div className="dashboard">

          <div className="dashboard-header">

            <div className="brand">
              <div className="shield">🛡️</div>
              <h1>CyberShield</h1>
            </div>

            <button
              className="logout-button"
              onClick={handleLogout}
            >
              Logout
            </button>

          </div>

          <button
            className="back-button"
            onClick={() => {
              setSelectedReport(null);
              loadReports();
            }}
          >
            ← Back to Reports
          </button>

          <SecurityReport
            result={selectedReport}
          />

        </div>

      </div>
    );
  }

  // ==================================================
  // SECURITY STATUS PAGE
  // ==================================================

  if (page === "status") {

    const totalScans = reports.length;

    const averageScore =
      totalScans > 0
        ? Math.round(
            reports.reduce(
              (sum, report) =>
                sum + report.security_score,
              0
            ) / totalScans
          )
        : 0;

    const goodReports = reports.filter(
      (report) => report.status === "Good"
    ).length;

    const poorReports = reports.filter(
      (report) => report.status === "Poor"
    ).length;

    return (
      <div className="app">

        <div className="dashboard">

          <div className="dashboard-header">

            <div className="brand">
              <div className="shield">🛡️</div>
              <h1>CyberShield</h1>
            </div>

            <button
              className="logout-button"
              onClick={handleLogout}
            >
              Logout
            </button>

          </div>

          <div className="page-heading">

            <h2>🛡️ Security Status</h2>

            <p>
              Overview of your previous CyberShield security scans.
            </p>

          </div>

          <button
            className="back-button"
            onClick={() => setPage("dashboard")}
          >
            ← Back to Dashboard
          </button>

          <div className="status-grid">

            <div className="status-card">
              <div className="status-icon">
                🔍
              </div>

              <h3>Total Scans</h3>

              <strong>
                {totalScans}
              </strong>

              <p>
                Security scans completed
              </p>
            </div>

            <div className="status-card">
              <div className="status-icon">
                📊
              </div>

              <h3>Average Score</h3>

              <strong>
                {averageScore}/100
              </strong>

              <p>
                Average security score
              </p>
            </div>

            <div className="status-card">
              <div className="status-icon">
                ✅
              </div>

              <h3>Good Scans</h3>

              <strong>
                {goodReports}
              </strong>

              <p>
                Scans with good status
              </p>
            </div>

            <div className="status-card">
              <div className="status-icon">
                ⚠️
              </div>

              <h3>Poor Scans</h3>

              <strong>
                {poorReports}
              </strong>

              <p>
                Scans requiring attention
              </p>
            </div>

          </div>

          <div className="status-explanation">

            <h2>What does this status mean?</h2>

            <p>
              CyberShield's security status is based on the
              domains you have scanned and the security
              protections detected during those scans.
            </p>

            <p>
              A low score does not automatically mean that a
              website has been hacked. It means that some of
              the security protections checked by CyberShield
              were not detected.
            </p>

            <p>
              For a complete assessment, additional security
              testing and professional security review may be
              required.
            </p>

          </div>

        </div>

      </div>
    );
  }

  return null;
}

export default App;