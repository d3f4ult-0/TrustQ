from fastapi import FastAPI
from pydantic import BaseModel
from datetime import datetime
from fastapi.middleware.cors import CORSMiddleware

from url_handler import (
    parse_url,
    is_valid_hostname,
    check_url_accessibility,
    analyze_url_structure
)

from rdap import get_registration_date
from ssl_check import get_ssl_certificate
from dns_check import check_dns
from headers_check import check_security_headers
from threat_intel import check_threat_intelligence
from scoring import calculate_score
from trust_level import get_trust_level


app = FastAPI()


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


class WebsiteRequest(BaseModel):
    domain: str


@app.get("/")
def home():
    return {
        "message": "TrustQ API is running"
    }


@app.post("/analyze")
def analyze_website(request: WebsiteRequest):

    # -------------------------
    # PARSE URL
    # -------------------------

    parsed_url, domain = parse_url(request.domain)

    if not parsed_url or not domain:
        return {
            "exists": False,
            "message": "Invalid website or URL."
        }

    if not is_valid_hostname(domain):
        return {
            "exists": False,
            "message": "Invalid website or hostname."
        }

    # -------------------------
    # URL SIGNALS
    # -------------------------

    url_signals = analyze_url_structure(parsed_url)

    # -------------------------
    # DNS
    # -------------------------

    ip_address, dns_valid = check_dns(domain)

    if not dns_valid:
        return {
            "domain": domain,
            "exists": False,
            "message": "Website does not exist or could not be resolved."
        }

    # -------------------------
    # ACCESSIBILITY + REDIRECTS
    # -------------------------

    accessible_url, https_worked, redirect_chain = check_url_accessibility(
        parsed_url.geturl()
    )

    if not accessible_url:
        return {
            "domain": domain,
            "exists": True,
            "message": "Domain exists, but the website could not be reached."
        }

    # -------------------------
    # FINAL DOMAIN
    # -------------------------

    final_parsed_url, final_domain = parse_url(accessible_url)

    if not final_domain:
        final_domain = domain

    # -------------------------
    # RDAP / DOMAIN AGE
    # -------------------------

    registration = get_registration_date(final_domain)

    if registration:
        domain_age = (
            datetime.now() - registration
        ).days
    else:
        domain_age = None

    # -------------------------
    # SSL
    # -------------------------

    certificate, expiry, ssl_valid = get_ssl_certificate(
        final_domain
    )

    # -------------------------
    # SECURITY HEADERS
    # -------------------------

    security_headers = check_security_headers(
        final_domain
    )

    # -------------------------
    # THREAT INTELLIGENCE
    # -------------------------

    threat_results = check_threat_intelligence(
        final_domain
    )

    # -------------------------
    # SCORING
    # -------------------------

    result = calculate_score(
        domain_age,
        ssl_valid,
        dns_valid,
        security_headers,
        threat_results,
        https_worked,
        url_signals
    )

    score = result["trust_score"]

    reasons = result["reasons"]

    confidence = result["confidence"]

    confidence_reasons = result["confidence_reasons"]

    # -------------------------
    # TRUST LEVEL
    # -------------------------

    trust_level = get_trust_level(score)

    # -------------------------
    # RETURN RESULT
    # -------------------------

    return {
        "exists": True,

        "domain": domain,

        "original_domain": domain,

        "final_domain": final_domain,

        "trust_quotient": score,

        "trust_level": trust_level,

        "confidence": confidence,

        "confidence_reasons": confidence_reasons,

        "reasons": reasons,

        "domain_age_days": domain_age,

        "ip_address": ip_address,

        "dns_valid": dns_valid,

        "https_worked": https_worked,

        "accessible_url": accessible_url,

        "redirect_chain": redirect_chain,

        "url_signals": url_signals,

        "ssl_valid": ssl_valid,

        "ssl_expiry": expiry,

        "security_headers": security_headers,

        "threat_intelligence": threat_results,

        "threat_intelligence_score": result[
            "threat_intelligence"
        ],

        "domain_reputation": result[
            "domain_reputation"
        ],

        "security_posture": result[
            "security_posture"
        ],

        "network_signals": result[
            "network_signals"
        ]
    }