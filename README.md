🛡️ CyberShield

CyberShield is a web-based cybersecurity monitoring and website security assessment platform. It allows users to scan a website, check HTTPS and important security headers, calculate a security score, and generate an easy-to-understand security report.

🚀 Live Demo

👉 https://cyber-shield-bay.vercel.app

📌 Features

- 🔐 User Signup and Login
- 🌐 Website / Domain Security Scanning
- 🔒 HTTPS Detection
- 🛡️ Security Header Detection
- 📊 Security Score out of 100
- 📋 Detailed Security Reports
- 💡 Security Recommendations
- 📄 Downloadable PDF Security Reports
- 🗂️ Saved Scan Reports
- 📱 Simple and User-Friendly Dashboard

🔍 Security Checks

CyberShield currently checks the following:

- HTTPS
- Content-Security-Policy
- X-Frame-Options
- X-Content-Type-Options
- Strict-Transport-Security
- Referrer-Policy

📊 Security Scoring

The security score is calculated out of 100.

| Security Check | Points |
|---|---:|
| HTTPS | 40 |
| Content-Security-Policy | 12 |
| X-Frame-Options | 12 |
| X-Content-Type-Options | 12 |
| Strict-Transport-Security | 12 |
| Referrer-Policy | 12 |
| **Total** | **100** |

Security Status

- 🟢 **80–100:** Good
- 🟡 **50–79:** Needs Improvement
- 🔴 **Below 50:** Poor

🏗️ Project Architecture

```text
User
  │
  ▼
React + Vite Frontend
  │
  ▼
FastAPI Backend
  │
  ├── Website Security Scanner
  ├── HTTPS & Header Checks
  ├── Score Calculation
  └── Report Generation
  │
  ▼
Neon PostgreSQL Database

🧰 Technologies Used

Frontend
React
Vite
JavaScript
CSS

Backend
Python
FastAPI
Uvicorn
HTTPX

Database
PostgreSQL
Neon

Database / ORM
SQLAlchemy

Authentication
Password Hashing
bcrypt

PDF Reports
jsPDF

Deployment & Version Control
Vercel
Git
GitHub

⚙️ How It Works
User creates an account or logs in.
User enters a website domain or URL.
CyberShield sends a request to the target website.
The backend checks HTTPS and selected security headers.
CyberShield calculates a security score.
The results are displayed in an easy-to-understand format.
The scan report is saved for the user.
Users can view previous reports and download a PDF report.

📄 Security Reports

Each report provides:

Website domain
HTTP status
HTTPS status
Security protections detected
Security score
Security status
Security findings
Risk information
Recommendations for improvement

🎯 Project Objective

The objective of CyberShield is to provide a simple and user-friendly platform for performing a basic automated security configuration assessment of websites and presenting the results in an understandable security report.

⚠️ Important Note

CyberShield performs a basic automated security configuration assessment based on HTTPS and selected HTTP security headers.

It is not a complete penetration-testing tool or a complete security audit, and a good CyberShield score does not guarantee that a website is completely secure.

👨‍💻 Project

CyberShield

GitHub Repository:
https://github.com/bhaskarlu63-pixel/CyberShield

Live Application:
https://cyber-shield-bay.vercel.app
