from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.orm import Session
from passlib.context import CryptContext

from database import engine, Base, SessionLocal
import models

import httpx
from urllib.parse import urlparse
import json


# ==================================================
# CREATE FASTAPI APPLICATION
# ==================================================

app = FastAPI(title="CyberShield API")


# ==================================================
# VERCEL SERVICES API PREFIX
# ==================================================

@app.middleware("http")
async def strip_vercel_prefix(request, call_next):
    if request.scope["path"].startswith("/svc/api"):
        request.scope["path"] = request.scope["path"][8:] or "/"
    return await call_next(request)


# ==================================================
# ALLOW REACT FRONTEND TO COMMUNICATE WITH BACKEND
# ==================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==================================================
# CREATE DATABASE TABLES
# ==================================================

Base.metadata.create_all(bind=engine)


# ==================================================
# PASSWORD HASHING
# ==================================================

pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto"
)


# ==================================================
# DATABASE CONNECTION
# ==================================================

def get_db():
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()


# ==================================================
# REQUEST MODELS
# ==================================================

class SignupRequest(BaseModel):
    username: str
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str


class SaveReportRequest(BaseModel):
    username: str
    domain: str
    status_code: int | None = None
    https_enabled: bool
    protections_detected: int
    protections_total: int
    security_score: int
    status: str
    findings: list


# ==================================================
# HOME / TEST API
# ==================================================

@app.get("/")
def home():
    return {
        "message": "CyberShield backend is running!"
    }


# ==================================================
# CREATE ACCOUNT
# ==================================================

@app.post("/signup")
def signup(
    user: SignupRequest,
    db: Session = Depends(get_db)
):

    username = user.username.strip()

    # Check username
    if not username:
        raise HTTPException(
            status_code=400,
            detail="Username cannot be empty"
        )

    # Check password
    if not user.password:
        raise HTTPException(
            status_code=400,
            detail="Password cannot be empty"
        )

    # bcrypt supports passwords up to 72 bytes
    if len(user.password.encode("utf-8")) > 72:
        raise HTTPException(
            status_code=400,
            detail="Password must be 72 bytes or fewer."
        )

    # Check whether username already exists
    existing_user = (
        db.query(models.User)
        .filter(
            models.User.username == username
        )
        .first()
    )

    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="Username already exists"
        )

    # Hash password
    hashed_password = pwd_context.hash(
        user.password
    )

    # Create user
    new_user = models.User(
        username=username,
        password_hash=hashed_password
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {
        "message": "Account created successfully"
    }


# ==================================================
# LOGIN
# ==================================================

@app.post("/login")
def login(
    user: LoginRequest,
    db: Session = Depends(get_db)
):

    username = user.username.strip()

    # Find user
    existing_user = (
        db.query(models.User)
        .filter(
            models.User.username == username
        )
        .first()
    )

    # Username doesn't exist
    if not existing_user:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )

    # Check password
    try:
        password_correct = pwd_context.verify(
            user.password,
            existing_user.password_hash
        )
    except ValueError:
        password_correct = False

    # Wrong password
    if not password_correct:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )

    return {
        "message": "Login successful",
        "username": existing_user.username
    }


# ==================================================
# DOMAIN SECURITY SCAN
# ==================================================

@app.get("/scan")
async def scan_domain(url: str):

    # Remove spaces
    url = url.strip()

    # Add HTTPS if user enters only domain
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:

        # Parse URL
        parsed = urlparse(url)

        if not parsed.netloc:
            raise HTTPException(
                status_code=400,
                detail="Invalid domain."
            )

        # Connect to website
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=10
        ) as client:

            response = await client.get(url)

        headers = response.headers


        # ==================================================
        # HTTPS CHECK
        # ==================================================

        https_enabled = response.url.scheme == "https"


        # ==================================================
        # SECURITY HEADERS CHECK
        # ==================================================

        security_headers = {

            "Content-Security-Policy":
                "content-security-policy" in headers,

            "X-Frame-Options":
                "x-frame-options" in headers,

            "X-Content-Type-Options":
                "x-content-type-options" in headers,

            "Strict-Transport-Security":
                "strict-transport-security" in headers,

            "Referrer-Policy":
                "referrer-policy" in headers,
        }


        # ==================================================
        # COUNT SECURITY HEADERS
        # ==================================================

        passed_headers = sum(
            security_headers.values()
        )

        total_headers = len(
            security_headers
        )


        # ==================================================
        # SECURITY SCORE
        # ==================================================

        score = 0

        # HTTPS = 40 points
        if https_enabled:
            score += 40

        # Security headers = 60 points
        if total_headers > 0:
            score += int(
                (passed_headers / total_headers) * 60
            )


        # ==================================================
        # SECURITY STATUS
        # ==================================================

        if score >= 80:
            status = "Good"

        elif score >= 50:
            status = "Needs Improvement"

        else:
            status = "Poor"


        # ==================================================
        # DETAILED SECURITY FINDINGS
        # ==================================================

        findings = []


        # --------------------------------------------------
        # HTTPS FINDING
        # --------------------------------------------------

        if https_enabled:

            findings.append({
                "name": "HTTPS",
                "title": "Secure HTTPS Connection",
                "technical_name": "HTTPS",
                "status": "Protection detected",
                "passed": True,
                "risk": "None",
                "what": (
                    "HTTPS encrypts communication between "
                    "the user's browser and the website."
                ),
                "why": (
                    "Encryption helps protect information "
                    "while it travels between the user "
                    "and the website."
                ),
                "recommendation": (
                    "Continue using HTTPS across the entire website."
                )
            })

        else:

            findings.append({
                "name": "HTTPS",
                "title": "Secure HTTPS Connection",
                "technical_name": "HTTPS",
                "status": "Protection not detected",
                "passed": False,
                "risk": "High",
                "what": (
                    "HTTPS helps encrypt information "
                    "sent between the browser and website."
                ),
                "why": (
                    "Without HTTPS, information may be "
                    "exposed while travelling between "
                    "the user and the website."
                ),
                "recommendation": (
                    "Configure the website to use HTTPS "
                    "and redirect HTTP traffic to HTTPS."
                )
            })


        # --------------------------------------------------
        # CONTENT SECURITY POLICY
        # --------------------------------------------------

        if security_headers["Content-Security-Policy"]:

            findings.append({
                "name": "Content Security Policy",
                "title": "Content Security Policy",
                "technical_name": "Content-Security-Policy",
                "status": "Protection detected",
                "passed": True,
                "risk": "None",
                "what": (
                    "Controls which scripts, images, styles "
                    "and other resources the website is "
                    "allowed to load."
                ),
                "why": (
                    "A well-configured policy can reduce "
                    "the impact of certain malicious "
                    "script injection attacks."
                ),
                "recommendation": (
                    "Review the policy regularly and allow "
                    "only resources the website actually needs."
                )
            })

        else:

            findings.append({
                "name": "Content Security Policy",
                "title": "Content Security Policy",
                "technical_name": "Content-Security-Policy",
                "status": "Protection not detected",
                "passed": False,
                "risk": "Medium",
                "what": (
                    "Controls which scripts, images, styles "
                    "and other resources the website is "
                    "allowed to load."
                ),
                "why": (
                    "A well-configured policy can reduce "
                    "the impact of certain malicious "
                    "script injection attacks."
                ),
                "recommendation": (
                    "Configure a Content-Security-Policy "
                    "that allows only the resources your "
                    "website actually needs."
                )
            })


        # --------------------------------------------------
        # CLICKJACKING PROTECTION
        # --------------------------------------------------

        if security_headers["X-Frame-Options"]:

            findings.append({
                "name": "Clickjacking Protection",
                "title": "Clickjacking Protection",
                "technical_name": "X-Frame-Options",
                "status": "Protection detected",
                "passed": True,
                "risk": "None",
                "what": (
                    "Controls whether your website can be "
                    "displayed inside a frame on another website."
                ),
                "why": (
                    "Framing protection can help reduce "
                    "the risk of clickjacking attacks."
                ),
                "recommendation": (
                    "Keep the framing policy correctly configured."
                )
            })

        else:

            findings.append({
                "name": "Clickjacking Protection",
                "title": "Clickjacking Protection",
                "technical_name": "X-Frame-Options",
                "status": "Protection not detected",
                "passed": False,
                "risk": "Medium",
                "what": (
                    "Controls whether your website can be "
                    "displayed inside a frame on another website."
                ),
                "why": (
                    "Suitable framing protection can help "
                    "reduce the risk of clickjacking attacks."
                ),
                "recommendation": (
                    "Configure X-Frame-Options or use the "
                    "Content-Security-Policy frame-ancestors directive."
                )
            })


        # --------------------------------------------------
        # CONTENT-TYPE PROTECTION
        # --------------------------------------------------

        if security_headers["X-Content-Type-Options"]:

            findings.append({
                "name": "Content-Type Protection",
                "title": "Content-Type Protection",
                "technical_name": "X-Content-Type-Options",
                "status": "Protection detected",
                "passed": True,
                "risk": "None",
                "what": (
                    "Tells browsers not to guess a file's content type."
                ),
                "why": (
                    "This can help reduce risks caused by "
                    "browsers interpreting files as a different "
                    "type than intended."
                ),
                "recommendation": (
                    "Keep X-Content-Type-Options configured correctly."
                )
            })

        else:

            findings.append({
                "name": "Content-Type Protection",
                "title": "Content-Type Protection",
                "technical_name": "X-Content-Type-Options",
                "status": "Protection not detected",
                "passed": False,
                "risk": "Low",
                "what": (
                    "Tells browsers not to guess a file's content type."
                ),
                "why": (
                    "This can help reduce risks caused by "
                    "browsers interpreting files as a different "
                    "type than intended."
                ),
                "recommendation": (
                    "Configure X-Content-Type-Options with "
                    "the value nosniff."
                )
            })


        # --------------------------------------------------
        # HSTS
        # --------------------------------------------------

        if security_headers["Strict-Transport-Security"]:

            findings.append({
                "name": "HTTPS Enforcement",
                "title": "HTTPS Enforcement (HSTS)",
                "technical_name": "Strict-Transport-Security",
                "status": "Protection detected",
                "passed": True,
                "risk": "None",
                "what": (
                    "Tells supported browsers to access "
                    "the website using HTTPS instead of "
                    "an unencrypted HTTP connection."
                ),
                "why": (
                    "It can help reduce the risk of users "
                    "being downgraded to an insecure HTTP connection."
                ),
                "recommendation": (
                    "Keep HSTS correctly configured."
                )
            })

        else:

            findings.append({
                "name": "HTTPS Enforcement",
                "title": "HTTPS Enforcement (HSTS)",
                "technical_name": "Strict-Transport-Security",
                "status": "Protection not detected",
                "passed": False,
                "risk": "Medium",
                "what": (
                    "Tells supported browsers to access "
                    "the website using HTTPS instead of "
                    "an unencrypted HTTP connection."
                ),
                "why": (
                    "It can help reduce the risk of users "
                    "being downgraded to an insecure HTTP connection."
                ),
                "recommendation": (
                    "After confirming the entire site works "
                    "correctly over HTTPS, consider configuring "
                    "an appropriate Strict-Transport-Security policy."
                )
            })


        # --------------------------------------------------
        # REFERRER POLICY
        # --------------------------------------------------

        if security_headers["Referrer-Policy"]:

            findings.append({
                "name": "Referrer Information Protection",
                "title": "Referrer Information Protection",
                "technical_name": "Referrer-Policy",
                "status": "Protection detected",
                "passed": True,
                "risk": "None",
                "what": (
                    "Controls how much information the browser "
                    "sends about the previous page when users "
                    "follow links."
                ),
                "why": (
                    "A suitable policy can reduce unnecessary "
                    "disclosure of browsing information."
                ),
                "recommendation": (
                    "Keep the referrer policy appropriately configured."
                )
            })

        else:

            findings.append({
                "name": "Referrer Information Protection",
                "title": "Referrer Information Protection",
                "technical_name": "Referrer-Policy",
                "status": "Protection not detected",
                "passed": False,
                "risk": "Low",
                "what": (
                    "Controls how much information the browser "
                    "sends about the previous page when users "
                    "follow links."
                ),
                "why": (
                    "A suitable policy can reduce unnecessary "
                    "disclosure of browsing information."
                ),
                "recommendation": (
                    "Configure a Referrer-Policy suitable for "
                    "the website, such as strict-origin-when-cross-origin."
                )
            })


        # ==================================================
        # RETURN COMPLETE SCAN RESULT
        # ==================================================

        return {

            "domain": parsed.netloc,

            "url": url,

            "status_code": response.status_code,

            "https_enabled": https_enabled,

            "security_headers": security_headers,

            "security_headers_passed": passed_headers,

            "security_headers_total": total_headers,

            "security_score": score,

            "status": status,

            "final_url": str(response.url),

            "findings": findings

        }


    except httpx.RequestError:

        raise HTTPException(
            status_code=400,
            detail="Unable to connect to the domain."
        )


# ==================================================
# SAVE SECURITY REPORT
# ==================================================

@app.post("/reports")
def save_report(
    report: SaveReportRequest,
    db: Session = Depends(get_db)
):

    # Find the user
    existing_user = (
        db.query(models.User)
        .filter(
            models.User.username == report.username
        )
        .first()
    )

    if not existing_user:
        raise HTTPException(
            status_code=404,
            detail="User not found."
        )


    # Create report
    new_report = models.ScanReport(

        user_id=existing_user.id,

        domain=report.domain,

        status_code=report.status_code,

        https_enabled=str(
            report.https_enabled
        ),

        protections_detected=(
            report.protections_detected
        ),

        protections_total=(
            report.protections_total
        ),

        security_score=(
            report.security_score
        ),

        status=report.status,

        findings=json.dumps(
            report.findings
        )
    )


    # Save report
    db.add(new_report)
    db.commit()
    db.refresh(new_report)


    return {
        "message": "Security report saved successfully.",
        "report_id": new_report.id
    }


# ==================================================
# GET USER'S SECURITY REPORTS
# ==================================================

@app.get("/reports/{username}")
def get_reports(
    username: str,
    db: Session = Depends(get_db)
):

    # Find user
    existing_user = (
        db.query(models.User)
        .filter(
            models.User.username == username
        )
        .first()
    )

    if not existing_user:
        raise HTTPException(
            status_code=404,
            detail="User not found."
        )


    # Get reports
    reports = (
        db.query(models.ScanReport)
        .filter(
            models.ScanReport.user_id == existing_user.id
        )
        .order_by(
            models.ScanReport.id.desc()
        )
        .all()
    )


    result = []


    for report in reports:

        try:
            findings = json.loads(
                report.findings
            ) if report.findings else []

        except json.JSONDecodeError:
            findings = []


        result.append({

            "id": report.id,

            "domain": report.domain,

            "status_code": report.status_code,

            "https_enabled":
                report.https_enabled == "True",

            "protections_detected":
                report.protections_detected,

            "protections_total":
                report.protections_total,

            "security_score":
                report.security_score,

            "status":
                report.status,

            "findings":
                findings

        })


    return {
        "reports": result
    }


# ==================================================
# GET ONE SECURITY REPORT
# ==================================================

@app.get("/report/{report_id}")
def get_single_report(
    report_id: int,
    db: Session = Depends(get_db)
):

    report = (
        db.query(models.ScanReport)
        .filter(
            models.ScanReport.id == report_id
        )
        .first()
    )


    if not report:
        raise HTTPException(
            status_code=404,
            detail="Security report not found."
        )


    try:

        findings = json.loads(
            report.findings
        ) if report.findings else []

    except json.JSONDecodeError:

        findings = []


    return {

        "id": report.id,

        "domain": report.domain,

        "status_code": report.status_code,

        "https_enabled":
            report.https_enabled == "True",

        "protections_detected":
            report.protections_detected,

        "protections_total":
            report.protections_total,

        "security_score":
            report.security_score,

        "status":
            report.status,

        "findings":
            findings

    }