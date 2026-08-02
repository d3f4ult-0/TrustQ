from fastapi import FastAPI
from pydantic import BaseModel
from datetime import datetime
from fastapi.middleware.cors import CORSMiddleware

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
    return {"message": "TrustQ API is running"}


@app.post("/analyze")
def analyze_website(request: WebsiteRequest):

    domain = request.domain

    # DNS
    ip_address, dns_valid = check_dns(domain)

    if not dns_valid:
        return {
            "domain": domain,
            "exists": False,
            "message": "Website does not exist or could not be resolved."
        }

    # RDAP / Domain Age
    registration = get_registration_date(domain)

    if registration:
        domain_age = (datetime.now() - registration).days
    else:
        domain_age = None

    # SSL
    certificate, expiry, ssl_valid = get_ssl_certificate(domain)

    # Security Headers
    security_headers = check_security_headers(domain)

    # Threat Intelligence
    threat_results = check_threat_intelligence(domain)

    # Score
    if domain_age is not None:
        score, reasons = calculate_score(
            domain_age,
            ssl_valid,
            dns_valid,
            security_headers,
            threat_results
        )
        trust_level = get_trust_level(score)
    else:
        score = None
        reasons = ["Domain registration date unavailable."]

    return {
    "exists": True,

    "domain": domain,

    "trust_quotient": score,

    "trust_level": trust_level,

    "reasons": reasons,

    "domain_age_days": domain_age,

    "ip_address": ip_address,

    "dns_valid": dns_valid,

    "ssl_valid": ssl_valid,

    "security_headers": security_headers,

    "threat_intelligence": threat_results
}
    