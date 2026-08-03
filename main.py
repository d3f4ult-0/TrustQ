from datetime import datetime

from url_handler import parse_url, is_valid_hostname, check_url_accessibility


from rdap import get_registration_date
from ssl_check import get_ssl_certificate
from dns_check import check_dns
from headers_check import check_security_headers
from threat_intel import check_threat_intelligence
from scoring import calculate_score


user_input = input("Enter the website or URL: ")

parsed_url, domain = parse_url(user_input)

if not parsed_url or not is_valid_hostname(domain):
    print("Invalid website or URL.")
    exit()

ip_address, dns_valid = check_dns(domain)

if not dns_valid:
    print("Website does not exist or has no DNS record.")
    exit()

accessible_url, https_worked = check_url_accessibility(domain)

if not accessible_url:
    print("Domain exists, but the website could not be reached.")
    exit()

print("Full URL:", accessible_url)
print("HTTPS:", "Available" if https_worked else "Unavailable")
print("Hostname:", domain)
print("IP Address:", ip_address)


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

result = calculate_score(
    domain_age,
    ssl_valid,
    dns_valid,
    security_headers,
    threat_results,
    https_worked
)

score = result["trust_score"]
reasons = result["reasons"]

print(f"Trust Quotient: {score}/100")
print(f"Threat Intelligence: {result['threat_intelligence']}/100")
print(f"Domain Reputation: {result['domain_reputation']}/100")
print(f"Security Posture: {result['security_posture']}/100")
print(f"Network Signals: {result['network_signals']}/100")

if reasons:
    print("Reasons:")
    for reason in reasons:
        print("-", reason)