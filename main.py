from datetime import datetime

from url_handler import (
    parse_url,
    is_valid_hostname,
    check_url_accessibility,
    analyze_url_structure,
    analyze_redirect_chain
)

from rdap import get_registration_date
from ssl_check import get_ssl_certificate
from dns_check import check_dns
from headers_check import check_security_headers
from threat_intel import check_threat_intelligence
from scoring import calculate_score


# -------------------------
# USER INPUT
# -------------------------

user_input = input("Enter the website or URL: ")

parsed_url, domain = parse_url(user_input)

if not parsed_url or not is_valid_hostname(domain):
    print("Invalid website or URL.")
    exit()

scheme = parsed_url.scheme
path = parsed_url.path
query = parsed_url.query


# -------------------------
# URL INTELLIGENCE
# -------------------------

url_signals = analyze_url_structure(parsed_url)




# -------------------------
# DNS CHECK
# -------------------------

ip_address, dns_valid = check_dns(domain)

if dns_valid is True:
    print("DNS Status: Domain resolved successfully.")

elif dns_valid is False:
    print("DNS Status: Domain does not resolve.")

else:
    print("DNS Status: Unable to determine.")
    print("Reason: DNS/network resolver unavailable.")


# -------------------------
# URL ACCESSIBILITY
# -------------------------

accessible_url, https_worked, redirect_chain, status_code = (
    check_url_accessibility(
        parsed_url.geturl()
    )
)
print("HTTP Status:", status_code)
if status_code == 404:
    print("URL Status: Page not found (404).")

elif status_code is not None and 400 <= status_code < 500:
    print(f"URL Status: Client error ({status_code}).")

elif status_code is not None and 500 <= status_code < 600:
    print(f"URL Status: Server error ({status_code}).")

elif status_code is not None and 200 <= status_code < 300:
    print(f"URL Status: Page reachable ({status_code}).")
redirect_signals = analyze_redirect_chain(
    redirect_chain
)

url_signals.extend(redirect_signals)

print("Redirect Chain:")
print("URL Signals:")

if url_signals:
    for signal in url_signals:
        print(
            f"- [{signal['severity'].upper()}] "
            f"{signal['message']}"
        )
else:
    print("- No unusual URL structure detected.")

for url in redirect_chain:
    print("-", url)

if not accessible_url:

    if dns_valid is False:
        print("Domain does not exist or has no DNS record.")

    elif dns_valid is None:
        print("Domain could not be verified.")
        print("Reason: DNS/network resolver unavailable.")

    else:
        print("Domain exists, but the website could not be reached.")

    exit()

final_parsed_url, final_domain = parse_url(accessible_url)

print("Full URL:", accessible_url)
print("HTTPS:", "Available" if https_worked else "Unavailable")
print("Original Hostname:", domain)
print("Final Hostname:", final_domain)
print("HTTPS:","Available" if https_worked else "Unavailable")
print("IP Address:", ip_address)


# -------------------------
# RDAP / DOMAIN AGE
# -------------------------

registration = get_registration_date(final_domain)

if registration:
    domain_age = (
        datetime.now() - registration
    ).days

    print(
        "Domain age:",
        domain_age,
        "days"
    )

else:
    domain_age = None

    print("Domain age: Unknown")


# -------------------------
# SSL CHECK
# -------------------------

certificate, expiry, ssl_valid = (get_ssl_certificate(final_domain))

print("SSL Valid:", ssl_valid)
print("SSL Expiry:", expiry)


# -------------------------
# SECURITY HEADERS
# -------------------------

security_headers = (check_security_headers(final_domain))

print(
    "HSTS:",
    "Present"
    if security_headers["hsts"]
    else "Not detected"
)

print(
    "CSP:",
    "Present"
    if security_headers["csp"]
    else "Not detected"
)

print(
    "CSP Report-Only:",
    "Present"
    if security_headers["csp_report_only"]
    else "Not detected"
)

print(
    "X-Content-Type-Options:",
    "Present"
    if security_headers["x_content_type_options"]
    else "Not detected"
)

print(
    "X-Frame-Options:",
    "Present"
    if security_headers["x_frame_options"]
    else "Not detected"
)


# -------------------------
# THREAT INTELLIGENCE
# -------------------------

threat_results = (check_threat_intelligence(final_domain))

print(
    "Threat Intelligence:",threat_results)


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
    url_signals,
    status_code
)


# -------------------------
# RESULTS
# -------------------------

score = result["trust_score"]
reasons = result["reasons"]
confidence = result["confidence"]
confidence_reasons = result["confidence_reasons"]


print(
    f"Trust Quotient: {score}/100"
)

print(
    f"Confidence: {confidence}"
)

print(
    f"Threat Intelligence: "
    f"{result['threat_intelligence']}/100"
)

print(
    f"Domain Reputation: "
    f"{result['domain_reputation']}/100"
)

print(
    f"Security Posture: "
    f"{result['security_posture']}/100"
)

print(
    f"Network Signals: "
    f"{result['network_signals']}/100"
)


# -------------------------
# REASONS
# -------------------------

if reasons:
    print("Reasons:")

    for reason in reasons:
        print("-", reason)


# -------------------------
# CONFIDENCE NOTES
# -------------------------

if confidence_reasons:
    print("Confidence Notes:")

    for reason in confidence_reasons:
        print("-", reason)