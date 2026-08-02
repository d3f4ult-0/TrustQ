from datetime import datetime

from rdap import get_registration_date
from ssl_check import get_ssl_certificate
from dns_check import check_dns
from headers_check import check_security_headers
from threat_intel import check_threat_intelligence
from scoring import calculate_score


domain = input("Enter the name of the website: ")


# RDAP / DOMAIN AGE
registration = get_registration_date(domain)

if registration:
    domain_age = (datetime.now() - registration).days
    print("Domain age:", domain_age, "days")
else:
    domain_age = None
    print("Domain age: Unknown")


# SSL CHECK
certificate, expiry, ssl_valid = get_ssl_certificate(domain)

print("SSL Valid:", ssl_valid)
print("SSL Expiry:", expiry)

# DNS CHECK
ip_address, dns_valid = check_dns(domain)

if not dns_valid:
    print("Website does not exist or could not be resolved.")
    exit()

print("IP Address:", ip_address)
print("DNS Valid:", dns_valid)

# SECURITY HEADERS
security_headers = check_security_headers(domain)

print(
    "HSTS:",
    "Present" if security_headers["hsts"] else "Not detected"
)

print(
    "CSP:",
    "Present" if security_headers["csp"] else "Not detected"
)

print(
    "CSP Report-Only:",
    "Present" if security_headers["csp_report_only"] else "Not detected"
)

print(
    "X-Content-Type-Options:",
    "Present" if security_headers["x_content_type_options"] else "Not detected"
)

print(
    "X-Frame-Options:",
    "Present" if security_headers["x_frame_options"] else "Not detected"
)


# THREAT INTELLIGENCE
threat_results = check_threat_intelligence(domain)

print("Threat Intelligence:", threat_results)


# SCORING
if domain_age is not None:

    score, reasons = calculate_score(
        domain_age,
        ssl_valid,
        dns_valid,
        security_headers,
        threat_results
    )

    print(f"Trust Quotient: {score}/100")

    if reasons:
        print("Reasons:")
        for reason in reasons:
            print("-", reason)

else:
    print("Trust Quotient: Unable to calculate.")
    print("Reason: Domain registration date unavailable.")