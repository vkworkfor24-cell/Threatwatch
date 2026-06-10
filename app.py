"""
ThreatWatch - Vulnerability Scanner Application
================================================
Root Code - Complete Backend Implementation
"""

# =============================================================================
# SECTION 1: Application Configuration
# =============================================================================

import os
from datetime import timedelta

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    """Base application configuration with environment-based settings."""

    # Secret keys
    SECRET_KEY = os.environ.get("SECRET_KEY", "super-secret-key-change-in-production")
    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "jwt-secret-key-change-in-production")

    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        "sqlite:///" + os.path.join(BASE_DIR, "threatwatch.db"),
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # JWT
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=24)

    # CORS
    CORS_HEADERS = "Content-Type"
    CORS_ORIGINS = os.environ.get("CORS_ORIGINS", "*")

    # Scan defaults
    SCAN_REQUEST_TIMEOUT = 20
    SCAN_RETRY_COUNT = 2
    SCAN_RETRY_DELAY = 1.0


class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True


class ProductionConfig(Config):
    """Production configuration."""
    DEBUG = False


class TestingConfig(Config):
    """Testing configuration."""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"


config_by_name = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
}


# =============================================================================
# SECTION 2: HTTP Status Codes
# =============================================================================

class HTTPSTATUS:
    """Standard HTTP status constants for consistent API responses."""

    # 1xx Informational
    CONTINUE = 100
    SWITCHING_PROTOCOLS = 101

    # 2xx Success
    OK = 200
    CREATED = 201
    ACCEPTED = 202
    NO_CONTENT = 204

    # 3xx Redirection
    MOVED_PERMANENTLY = 301
    FOUND = 302
    NOT_MODIFIED = 304

    # 4xx Client Errors
    BAD_REQUEST = 400
    UNAUTHORIZED = 401
    FORBIDDEN = 403
    NOT_FOUND = 404
    METHOD_NOT_ALLOWED = 405
    CONFLICT = 409
    UNPROCESSABLE_ENTITY = 422
    TOO_MANY_REQUESTS = 429

    # 5xx Server Errors
    INTERNAL_SERVER_ERROR = 500
    NOT_IMPLEMENTED = 501
    BAD_GATEWAY = 502
    SERVICE_UNAVAILABLE = 503


# =============================================================================
# SECTION 3: Application Errors
# =============================================================================

class AppError(Exception):
    """Base application error with HTTP status code."""

    def __init__(self, message: str, status_code: int = HTTPSTATUS.INTERNAL_SERVER_ERROR):
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)


class BadRequestException(AppError):
    def __init__(self, message: str = "Bad request"):
        super().__init__(message, HTTPSTATUS.BAD_REQUEST)


class UnauthorizedException(AppError):
    def __init__(self, message: str = "Unauthorized"):
        super().__init__(message, HTTPSTATUS.UNAUTHORIZED)


class ForbiddenException(AppError):
    def __init__(self, message: str = "Forbidden"):
        super().__init__(message, HTTPSTATUS.FORBIDDEN)


class NotFoundException(AppError):
    def __init__(self, message: str = "Resource not found"):
        super().__init__(message, HTTPSTATUS.NOT_FOUND)


class ConflictException(AppError):
    def __init__(self, message: str = "Resource already exists"):
        super().__init__(message, HTTPSTATUS.CONFLICT)


class ValidationException(AppError):
    def __init__(self, message: str = "Validation failed", errors: list | None = None):
        super().__init__(message, HTTPSTATUS.UNPROCESSABLE_ENTITY)
        self.errors = errors or []


# =============================================================================
# SECTION 4: Flask Extensions
# =============================================================================

from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate

db = SQLAlchemy()
jwt = JWTManager()
cors = CORS()
bcrypt = Bcrypt()
migrate = Migrate()


# =============================================================================
# SECTION 5: Database Models
# =============================================================================

from datetime import datetime


class User(db.Model):
    """Represents an authenticated user."""

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)


def get_user_by_id(uid: int) -> User | None:
    """Retrieve a user by their primary key."""
    return User.query.get(uid)


class Scan(db.Model):
    """Represents a security scan result."""

    __tablename__ = "scans"

    id = db.Column(db.Integer, primary_key=True)
    target_url = db.Column(db.String(255), nullable=False)
    result = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Alert(db.Model):
    """Represents a security alert associated with a scan."""

    __tablename__ = "alerts"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"))
    message = db.Column(db.String(255), nullable=False)
    severity = db.Column(db.String(20), default="low")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    scan = db.relationship("Scan", backref="alerts")


# =============================================================================
# SECTION 6: Middlewares
# =============================================================================

from flask import jsonify
from functools import wraps
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity


def error_handler(app):
    """Register global error handlers on the Flask app."""

    @app.errorhandler(AppError)
    def handle_app_error(error):
        return jsonify({
            "error": error.message,
            "status_code": error.status_code,
        }), error.status_code

    @app.errorhandler(404)
    def handle_not_found(error):
        return jsonify({
            "error": "The requested resource was not found",
            "status_code": HTTPSTATUS.NOT_FOUND,
        }), HTTPSTATUS.NOT_FOUND

    @app.errorhandler(405)
    def handle_method_not_allowed(error):
        return jsonify({
            "error": "Method not allowed",
            "status_code": HTTPSTATUS.METHOD_NOT_ALLOWED,
        }), HTTPSTATUS.METHOD_NOT_ALLOWED

    @app.errorhandler(429)
    def handle_rate_limit(error):
        return jsonify({
            "error": "Too many requests. Please try again later.",
            "status_code": HTTPSTATUS.TOO_MANY_REQUESTS,
        }), HTTPSTATUS.TOO_MANY_REQUESTS

    @app.errorhandler(Exception)
    def handle_unexpected(error):
        app.logger.error(f"Unhandled error: {str(error)}")
        return jsonify({
            "error": "An internal server error occurred",
            "status_code": HTTPSTATUS.INTERNAL_SERVER_ERROR,
        }), HTTPSTATUS.INTERNAL_SERVER_ERROR


def jwt_required(fn):
    """Decorator that ensures a valid JWT is present in the request."""

    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            verify_jwt_in_request()
        except Exception:
            raise UnauthorizedException("Authentication required. Please provide a valid token.")
        return fn(*args, **kwargs)
    return wrapper


def get_current_user_id():
    """Get the current authenticated user's ID from the JWT."""
    return get_jwt_identity()


# =============================================================================
# SECTION 7: Services - Vulnerability Scanner
# =============================================================================

import re
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from urllib.parse import urlparse, urljoin, parse_qs
import requests
from bs4 import BeautifulSoup
import time

REQUEST_TIMEOUT = 20
RETRY_COUNT = 2
RETRY_DELAY = 1.0

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/122.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
}

SQL_ERROR_SIGNS = [
    "sql syntax", "mysql", "pdoexception", "syntaxerror",
    "unterminated string", "odbc", "databaseerror",
    "warning: mysql", "you have an error in your sql syntax",
]


def normalize_url(raw):
    """Normalize URL by adding scheme if missing."""
    if not raw:
        return None
    raw = raw.strip()
    parsed = urlparse(raw)
    if parsed.scheme:
        return raw
    return "https://" + raw


def safe_get(url, params=None, headers=None):
    """
    Fetch URL with retries and scheme fallback.
    Returns Response on success (including 4xx/5xx), None on network failure.
    """
    if not url:
        return None
    url = normalize_url(url)
    hdrs = DEFAULT_HEADERS.copy()
    if headers:
        hdrs.update(headers)
    last_exc = None
    session = requests.Session()
    session.headers.update(hdrs)
    for attempt in range(RETRY_COUNT + 1):
        try:
            r = session.get(url, params=params, timeout=REQUEST_TIMEOUT,
                            allow_redirects=True, verify=False)
            return r
        except requests.exceptions.RequestException as e:
            last_exc = e
            time.sleep(RETRY_DELAY)
            continue
    parsed = urlparse(url)
    if parsed.scheme == "https":
        try:
            fallback = url.replace("https://", "http://", 1)
            r = session.get(fallback, params=params, timeout=REQUEST_TIMEOUT,
                            allow_redirects=True, verify=False)
            return r
        except requests.exceptions.RequestException:
            pass
    print("safe_get error:", last_exc)
    return None


def extract_links(html_text, base_url):
    """Extract all hyperlinks from HTML."""
    links = set()
    if not html_text:
        return []
    try:
        soup = BeautifulSoup(html_text, "lxml")
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if href.startswith("javascript:") or href.startswith("mailto:"):
                continue
            full = urljoin(base_url, href)
            links.add(full.split("#")[0])
    except Exception:
        pass
    return list(links)


def get_title(html_text):
    """Extract page title from HTML."""
    if not html_text:
        return ""
    try:
        soup = BeautifulSoup(html_text, "lxml")
        return soup.title.string.strip() if soup.title and soup.title.string else ""
    except Exception:
        return ""


def check_security_headers(resp):
    """Check for missing security headers in response."""
    if resp is None:
        return {"missing": ["(no response)"], "present": {}}
    headers = resp.headers or {}
    missing = []
    for h in ["Content-Security-Policy", "X-Content-Type-Options",
              "X-Frame-Options", "Strict-Transport-Security"]:
        if h not in headers:
            missing.append(h)
    return {"missing": missing, "present": {k: headers.get(k) for k in headers}}


def check_cors(url):
    """Check CORS configuration by sending a cross-origin request."""
    try:
        r = requests.get(url, headers={"Origin": "http://evil.example.com", **DEFAULT_HEADERS},
                         timeout=REQUEST_TIMEOUT, verify=False)
        return {
            "origin_header": r.headers.get("Access-Control-Allow-Origin"),
            "credentials": r.headers.get("Access-Control-Allow-Credentials"),
        }
    except Exception:
        return {"origin_header": None}


def passive_sql_errors(text):
    """Detect SQL error messages in response text."""
    if not text:
        return {"found": False, "matches": []}
    found = []
    low = text.lower()
    for sig in SQL_ERROR_SIGNS:
        if sig in low:
            found.append(sig)
    return {"found": bool(found), "matches": found}


def passive_xss_reflection(url, resp):
    """Test for XSS reflection by sending a sentinel value in query params."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    if not qs:
        return {"tested": False, "reason": "no query params"}
    param = next(iter(qs.keys()))
    sentinel = "TW_SENTINEL_98765"
    params = {**qs}
    params[param] = sentinel
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    r = safe_get(base, params=params)
    if not r:
        return {"tested": True, "vulnerable": False, "reason": "no response"}
    if sentinel in (r.text or ""):
        return {"tested": True, "vulnerable": True, "parameter": param}
    low = (r.text or "").lower()
    for kw in ["<script", "onerror=", "onload=", "alert(", "document.cookie"]:
        if kw in low:
            return {"tested": True, "vulnerable": "possible_context", "evidence": kw}
    return {"tested": True, "vulnerable": False}


def open_redirect_analysis(base_url, html_text):
    """Analyze links for open redirect vulnerabilities."""
    findings = []
    links = extract_links(html_text, base_url)
    base_host = urlparse(base_url).netloc
    for link in links:
        p = urlparse(link)
        if p.netloc and p.netloc != base_host:
            findings.append({"type": "external_link", "url": link})
    redirect_param_names = ["redirect", "next", "url", "goto", "return"]
    for link in links:
        q = parse_qs(urlparse(link).query)
        for pnm in redirect_param_names:
            if pnm in q:
                vals = q.get(pnm) or []
                for v in vals:
                    if v and urlparse(v).netloc and urlparse(v).netloc != base_host:
                        findings.append({"type": "redirect_param", "param": pnm, "value": v, "url": link})
    return {"findings": findings}


def ssrf_indicators(text):
    """Check for SSRF indicators in response."""
    if not text:
        return {"found": False}
    low = text.lower()
    for sig in ["169.254.169.254", "metadata", "instance-id", "/latest/meta-data"]:
        if sig in low:
            return {"found": True, "evidence": sig}
    return {"found": False}


def basic_scan(url):
    """Run a full vulnerability scan against the target URL."""
    result = {
        "target": url, "status_code": None, "content_type": None,
        "title": None, "link_count": 0, "security_headers": {},
        "cors": {}, "sql_errors": {}, "xss_reflection": {},
        "open_redirects": {}, "ssrf": {},
    }
    r = safe_get(url)
    if not r:
        result["error"] = "failed_to_fetch"
        return result
    result["status_code"] = getattr(r, "status_code", None)
    result["content_type"] = r.headers.get("content-type") if r.headers else None
    result["title"] = get_title(r.text)
    result["link_count"] = len(extract_links(r.text, url))
    result["security_headers"] = check_security_headers(r)
    result["cors"] = check_cors(url)
    result["sql_errors"] = passive_sql_errors(r.text)
    try:
        result["xss_reflection"] = passive_xss_reflection(url, r)
    except Exception as e:
        result["xss_reflection"] = {"tested": False, "error": str(e)}
    try:
        result["open_redirects"] = open_redirect_analysis(url, r.text)
    except Exception as e:
        result["open_redirects"] = {"error": str(e)}
    result["ssrf"] = ssrf_indicators(r.text)
    return result


def scan_xss_only(url):
    """Scan for XSS vulnerabilities only."""
    r = safe_get(url)
    if not r:
        return {"error": "failed_to_fetch", "target": url}
    return {"target": url, "xss_reflection": passive_xss_reflection(url, r)}


def scan_sqli_only(url):
    """Scan for SQL injection only."""
    r = safe_get(url)
    if not r:
        return {"error": "failed_to_fetch", "target": url}
    return {"target": url, "sql_errors": passive_sql_errors(r.text)}


def scan_cors_only(url):
    """Check CORS configuration only."""
    return {"target": url, "cors": check_cors(url)}


def scan_open_redirect_only(url):
    """Check for open redirects only."""
    r = safe_get(url)
    if not r:
        return {"error": "failed_to_fetch", "target": url}
    return {"target": url, "open_redirects": open_redirect_analysis(url, r.text)}


def scan_security_headers_only(url):
    """Check security headers only."""
    r = safe_get(url)
    if not r:
        return {"error": "failed_to_fetch", "target": url}
    return {"target": url, "security_headers": check_security_headers(r)}


def scan_ssrf_only(url):
    """Check for SSRF indicators only."""
    r = safe_get(url)
    if not r:
        return {"error": "failed_to_fetch", "target": url}
    return {"target": url, "ssrf": ssrf_indicators(r.text)}


# =============================================================================
# SECTION 8: Services - PDF Report Generator
# =============================================================================

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
import io, json
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

CYBER_BLUE = (0/255, 255/255, 255/255)
CYBER_PINK = (255/255, 0/255, 255/255)
CYBER_BG = (10/255, 10/255, 20/255)
WHITE = (1, 1, 1)


def compute_risk(result):
    """Compute risk score based on detected vulnerabilities."""
    risk = 0
    if result.get("sql_errors", {}).get("found"):
        risk += 40
    x = result.get("xss_reflection", {})
    if x.get("vulnerable") is True:
        risk += 30
    if len(result.get("open_redirects", {}).get("findings", [])) > 0:
        risk += 15
    if len(result.get("security_headers", {}).get("missing", [])) > 0:
        risk += 10
    if result.get("ssrf", {}).get("found"):
        risk += 25
    return min(risk, 100)


def generate_pie_chart(result):
    """Generate a pie chart of detected vulnerabilities."""
    labels, sizes = [], []
    if result.get("sql_errors", {}).get("found"):
        labels.append("SQLi"); sizes.append(1)
    if result.get("xss_reflection", {}).get("vulnerable"):
        labels.append("XSS"); sizes.append(1)
    if len(result.get("open_redirects", {}).get("findings", [])) > 0:
        labels.append("Open Redirect"); sizes.append(1)
    if result.get("ssrf", {}).get("found"):
        labels.append("SSRF"); sizes.append(1)
    if not labels:
        labels = ["No Vulnerabilities"]; sizes = [1]
    fig, ax = plt.subplots(figsize=(3, 3))
    ax.pie(sizes, labels=labels, autopct='%1.1f%%', textprops={'color': 'white'})
    fig.patch.set_facecolor('#0a0a14')
    plt.tight_layout()
    img_bytes = io.BytesIO()
    plt.savefig(img_bytes, format='png', dpi=150, transparent=False, facecolor=fig.get_facecolor())
    plt.close()
    img_bytes.seek(0)
    return img_bytes


def generate_pdf_report(scan, result):
    """Generate a professional PDF scan report."""
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    width, height = A4
    # Header bar
    c.setFillColorRGB(*CYBER_BG)
    c.rect(0, height - 70, width, 70, fill=1, stroke=0)
    c.setFillColorRGB(*CYBER_BLUE)
    c.setFont("Helvetica-Bold", 26)
    c.drawString(30, height - 45, "ThreatWatch Report")
    # Meta info
    y = height - 100
    c.setFillColorRGB(1, 1, 1)
    c.setFont("Helvetica-Bold", 12)
    c.drawString(30, y, f"Scan ID: {scan.id}")
    c.setFont("Helvetica", 11)
    c.drawString(30, y - 18, f"Target: {scan.target_url}")
    c.drawString(30, y - 36, f"Date: {scan.created_at}")
    c.drawString(30, y - 54, f"User Email: {result.get('user_email', 'Unknown')}")
    c.drawString(30, y - 72, f"Scan Type: {result.get('scan_type', 'Full Scan')}")
    y -= 110
    # Risk score
    risk = compute_risk(result)
    c.setFont("Helvetica-Bold", 14)
    c.setFillColorRGB(*CYBER_PINK)
    c.drawString(30, y, f"Risk Score: {risk}/100")
    y -= 30
    # Vulnerability summary
    c.setFillColorRGB(1, 1, 1)
    c.setFont("Helvetica-Bold", 13)
    c.drawString(30, y, "Vulnerability Summary:")
    y -= 20

    def write(label, value):
        nonlocal y
        c.setFont("Helvetica-Bold", 11)
        c.setFillColorRGB(*CYBER_BLUE)
        c.drawString(36, y, f"{label}:")
        c.setFillColorRGB(1, 1, 1)
        c.setFont("Helvetica", 11)
        c.drawString(180, y, str(value))
        y -= 18

    write("SQL Injection", "Yes" if result.get("sql_errors", {}).get("found") else "No")
    write("XSS", "Yes" if result.get("xss_reflection", {}).get("vulnerable") else "No")
    write("Open Redirects", len(result.get("open_redirects", {}).get("findings", [])))
    write("SSRF", "Yes" if result.get("ssrf", {}).get("found") else "No")
    write("Missing Headers", len(result.get("security_headers", {}).get("missing", [])))
    # Pie chart
    chart = generate_pie_chart(result)
    c.drawInlineImage(chart, 350, y - 10, width=180, height=180)
    # JSON result on new page
    c.showPage()
    c.setFillColorRGB(*CYBER_BLUE)
    c.setFont("Helvetica-Bold", 16)
    c.drawString(30, height - 40, "Full JSON Result")
    c.setFillColorRGB(1, 1, 1)
    c.setFont("Courier", 8)
    js = json.dumps(result, indent=2)[:15000]
    text = c.beginText(30, height - 60)
    for line in js.splitlines():
        text.textLine(line)
    c.drawText(text)
    c.save()
    pdf = buf.getvalue()
    buf.close()
    return pdf


# =============================================================================
# SECTION 9: Controllers
# =============================================================================

from flask import Flask, Blueprint, jsonify, request, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token
import ast
import logging

logger = logging.getLogger(__name__)


class AuthController:
    """Controller for authentication endpoints."""

    @staticmethod
    def register():
        """
        POST /api/auth/register
        Body: { email: string, password: string }
        """
        data = request.get_json() or {}
        email = data.get("email")
        password = data.get("password")
        if not email or not password:
            raise BadRequestException("Email and password are required")
        existing = User.query.filter_by(email=email).first()
        if existing:
            raise ConflictException("User with this email already exists")
        hashed = generate_password_hash(password)
        user = User(email=email, password=hashed)
        db.session.add(user)
        db.session.commit()
        return jsonify({
            "message": "User registered successfully",
            "user": {"id": user.id, "email": user.email},
        }), HTTPSTATUS.CREATED

    @staticmethod
    def login():
        """
        POST /api/auth/login
        Body: { email: string, password: string }
        """
        data = request.get_json() or {}
        email = data.get("email")
        password = data.get("password")
        if not email or not password:
            raise BadRequestException("Email and password are required")
        user = User.query.filter_by(email=email).first()
        if not user or not check_password_hash(user.password, password):
            raise UnauthorizedException("Invalid email or password")
        token = create_access_token(identity=user.id)
        return jsonify({
            "message": "Login successful",
            "token": token,
            "user": {"id": user.id, "email": user.email},
        }), HTTPSTATUS.OK


class ScanController:
    """Controller for vulnerability scanning endpoints."""

    @staticmethod
    def start_full_scan():
        """POST /api/scan/start - Run a full vulnerability scan."""
        data = request.get_json() or {}
        if not data.get("url"):
            raise BadRequestException("URL is required")
        url = data["url"]
        result = basic_scan(url)
        scan_id = ScanController._save_scan(url, result)
        return jsonify({
            "message": "Scan completed successfully",
            "scan_id": scan_id,
            "result": result,
        }), HTTPSTATUS.OK

    @staticmethod
    def scan_xss():
        return ScanController._run_single_scan("xss", scan_xss_only)

    @staticmethod
    def scan_sqli():
        return ScanController._run_single_scan("sqli", scan_sqli_only)

    @staticmethod
    def scan_cors():
        return ScanController._run_single_scan("cors", scan_cors_only)

    @staticmethod
    def scan_open_redirect():
        return ScanController._run_single_scan("openredirect", scan_open_redirect_only)

    @staticmethod
    def scan_headers():
        return ScanController._run_single_scan("headers", scan_security_headers_only)

    @staticmethod
    def scan_ssrf():
        return ScanController._run_single_scan("ssrf", scan_ssrf_only)

    @staticmethod
    def list_scans():
        """GET /api/scan/list - List all scans."""
        scans = Scan.query.order_by(Scan.id.desc()).all()
        return jsonify([{
            "id": s.id, "target_url": s.target_url,
            "result": s.result, "created_at": str(s.created_at),
        } for s in scans]), HTTPSTATUS.OK

    @staticmethod
    def get_scan(scan_id: int):
        """GET /api/scan/<id> - Get a single scan by ID."""
        scan = Scan.query.get(scan_id)
        if not scan:
            raise NotFoundException(f"Scan with ID {scan_id} not found")
        return jsonify({
            "id": scan.id, "target_url": scan.target_url,
            "result": scan.result, "created_at": str(scan.created_at),
        }), HTTPSTATUS.OK

    @staticmethod
    def download_report(scan_id: int):
        """GET /api/scan/report/<id> - Download PDF report."""
        scan = Scan.query.get(scan_id)
        if not scan:
            raise NotFoundException(f"Scan with ID {scan_id} not found")
        try:
            result_obj = ast.literal_eval(scan.result)
        except Exception:
            result_obj = {"raw": scan.result}
        pdf_bytes = generate_pdf_report(scan=scan, result=result_obj)
        return send_file(
            io.BytesIO(pdf_bytes),
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"threatwatch_scan_{scan_id}.pdf",
        )

    # ── Private helpers ─────────────────────────────────────────────────

    @staticmethod
    def _run_single_scan(scan_type: str, scan_func):
        data = request.get_json() or {}
        url = data.get("url")
        if not url:
            raise BadRequestException("URL is required")
        result = scan_func(url)
        scan_id = ScanController._save_scan(url, result)
        return jsonify({
            "message": f"{scan_type.upper()} scan completed",
            "scan_id": scan_id,
            "result": result,
        }), HTTPSTATUS.OK

    @staticmethod
    def _save_scan(url: str, result: dict) -> int | None:
        try:
            scan = Scan(target_url=url, result=str(result))
            db.session.add(scan)
            db.session.commit()
            return scan.id
        except Exception as exc:
            db.session.rollback()
            logger.warning(f"Failed to persist scan result: {exc}")
            return None


class UserController:
    """Controller for user-related endpoints."""

    @staticmethod
    def get_profile():
        """GET /api/user/me - Get authenticated user's profile."""
        user_id = get_current_user_id()
        user = get_user_by_id(user_id)
        if not user:
            raise NotFoundException("User not found")
        return jsonify({"id": user.id, "email": user.email}), HTTPSTATUS.OK

    @staticmethod
    def get_scans():
        """GET /api/user/scans - Get all scans."""
        scans = Scan.query.order_by(Scan.id.desc()).all()
        return jsonify([{
            "id": s.id, "target_url": s.target_url,
            "result": s.result, "created_at": str(s.created_at),
        } for s in scans]), HTTPSTATUS.OK


class StatsController:
    """Controller for analytics and statistics endpoints."""

    @staticmethod
    def get_summary():
        """GET /api/stats/summary - Get dashboard statistics."""
        now = datetime.utcnow()
        day_ago = now - timedelta(days=1)
        scans_24h = Scan.query.filter(Scan.created_at >= day_ago).count()
        counts = {"xss": 0, "sqli": 0, "open_redirect": 0}
        total_vulns = 0
        scans = Scan.query.order_by(Scan.id.desc()).limit(200).all()
        for s in scans:
            try:
                res = ast.literal_eval(s.result)
            except Exception:
                continue
            if res.get("xss_reflection", {}).get("found"):
                counts["xss"] += 1; total_vulns += 1
            if res.get("sql_errors", {}).get("found"):
                counts["sqli"] += 1; total_vulns += 1
            if len(res.get("open_redirects", {}).get("findings", [])) > 0:
                counts["open_redirect"] += 1; total_vulns += 1
        daily = []
        for i in range(6, -1, -1):
            day = (now - timedelta(days=i)).strftime("%Y-%m-%d")
            daily.append({"day": day, "scans": 0})
        return jsonify({
            "scans_24h": scans_24h, "counts": counts,
            "total_vulns": total_vulns, "high": 0, "daily": daily,
        }), HTTPSTATUS.OK


class HealthController:
    """Controller for health check endpoints."""

    @staticmethod
    def check():
        """GET /api/health - Check backend status."""
        return jsonify({
            "status": "ok",
            "message": "ThreatWatch backend running",
        }), HTTPSTATUS.OK


# =============================================================================
# SECTION 10: Routes (URL Mappings)
# =============================================================================

auth_bp = Blueprint("auth_bp", __name__, url_prefix="/api/auth")
auth_bp.add_url_rule("/register", view_func=AuthController.register, methods=["POST"])
auth_bp.add_url_rule("/login", view_func=AuthController.login, methods=["POST"])

user_bp = Blueprint("user_bp", __name__, url_prefix="/api/user")
user_bp.add_url_rule("/me", view_func=jwt_required(UserController.get_profile), methods=["GET"])
user_bp.add_url_rule("/scans", view_func=jwt_required(UserController.get_scans), methods=["GET"])

scan_bp = Blueprint("scan_bp", __name__, url_prefix="/api/scan")
scan_bp.add_url_rule("/start", view_func=ScanController.start_full_scan, methods=["POST"])
scan_bp.add_url_rule("/xss", view_func=ScanController.scan_xss, methods=["POST"])
scan_bp.add_url_rule("/sqli", view_func=ScanController.scan_sqli, methods=["POST"])
scan_bp.add_url_rule("/cors", view_func=ScanController.scan_cors, methods=["POST"])
scan_bp.add_url_rule("/openredirect", view_func=ScanController.scan_open_redirect, methods=["POST"])
scan_bp.add_url_rule("/headers", view_func=ScanController.scan_headers, methods=["POST"])
scan_bp.add_url_rule("/ssrf", view_func=ScanController.scan_ssrf, methods=["POST"])
scan_bp.add_url_rule("/list", view_func=ScanController.list_scans, methods=["GET"])
scan_bp.add_url_rule("/<int:scan_id>", view_func=ScanController.get_scan, methods=["GET"])
scan_bp.add_url_rule("/report/<int:scan_id>", view_func=ScanController.download_report, methods=["GET"])

stats_bp = Blueprint("stats_bp", __name__, url_prefix="/api/stats")
stats_bp.add_url_rule("/summary", view_func=StatsController.get_summary, methods=["GET"])

health_bp = Blueprint("health", __name__)
health_bp.add_url_rule("/api/health", view_func=HealthController.check, methods=["GET"])


# =============================================================================
# SECTION 11: Application Factory & Entry Point
# =============================================================================

def create_app(config_class=Config):
    """Create and configure the Flask application."""3
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize extensions
    db.init_app(app)
    jwt.init_app(app)
    cors.init_app(app)
    migrate.init_app(app, db)

    # Register global error handlers
    error_handler(app)

    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(user_bp)
    app.register_blueprint(scan_bp)
    app.register_blueprint(health_bp)
    app.register_blueprint(stats_bp)

    return app


# Main entry point
if __name__ == "__main__":
    app = create_app()
    print("ThreatWatch backend starting on http://0.0.0.0:5000")
    print("Registered routes:")
    for rule in sorted(app.url_map.iter_rules(), key=lambda x: x.rule):
        methods = rule.methods - {"OPTIONS", "HEAD"}
        if methods:
            print(f"  {methods} {rule.rule}")
    app.run(debug=True, host="0.0.0.0", port=5000)
