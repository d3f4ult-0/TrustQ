def calculate_score(domain_age, ssl_valid, dns_valid, security_headers, threat_results, https_worked):
    
    reasons = []
    
    threat_intelligence = 0
    domain_reputation = 0
    security_posture = 0
    network_signals = 0

    # Domain Reputation

    if domain_age is None:
        domain_reputation = 50
        reasons.append(
        "Domain registration date is unavailable; "
        "domain reputation confidence is reduced."
    )

    elif domain_age < 7:    
        domain_reputation = 0
        reasons.append("Domain is less than 7 days old.")

    elif domain_age <= 30:
        domain_reputation = 25
        reasons.append("Domain is less than 30 days old.")

    elif domain_age <= 180:
        domain_reputation = 50
        reasons.append("Domain is between 31 and 180 days old.")

    elif domain_age <= 365:
        domain_reputation = 70
        reasons.append("Domain is between 181 days and 1 year old.")

    elif domain_age <= 1095:
        domain_reputation = 85
        reasons.append("Domain is between 1 and 3 years old.")

    else:
        domain_reputation = 100
        reasons.append("Domain is more than 3 years old.")

# Security Posture

    security_posture = 0

    if ssl_valid:
        security_posture += 40
        reasons.append("SSL certificate is valid.")
    else:
        reasons.append("SSL certificate is invalid or expired.")

    if https_worked:
        security_posture += 20
        reasons.append("HTTPS is accessible.")
    else:
        reasons.append("HTTPS is unavailable; HTTP fallback was used.")

    if security_headers["hsts"]:
        security_posture += 15
        reasons.append("HSTS is present.")

    if security_headers["csp"]:
        security_posture += 15
        reasons.append("Content Security Policy is present.")

    if security_headers["x_content_type_options"]:
        security_posture += 5
        reasons.append("X-Content-Type-Options is present.")

    if security_headers["x_frame_options"]:
        security_posture += 5
        reasons.append("X-Frame-Options is present.")

    if security_headers["csp_report_only"]:
        reasons.append("Content Security Policy is in report-only mode.")

    # Network Signals

    network_signals = 0

    if dns_valid:
        network_signals += 100
        reasons.append("Domain resolves successfully through DNS.")
    else:
        reasons.append(
        "Domain could not be resolved through DNS. "
        "This may be caused by DNS failure or network-level filtering."
    )

    # Threat Intelligence

    threat_intelligence = 100

    if threat_results.get("google_safe_browsing"):
        threat_intelligence -= 50
        reasons.append("Google Safe Browsing detected a threat.")
    else:
        reasons.append("Google Safe Browsing found no known threat.")

    if threat_results.get("openphish"):
        threat_intelligence -= 50
        reasons.append("OpenPhish detected a known phishing URL.")
    else:
        reasons.append("OpenPhish found no known phishing match.")

    threat_intelligence = max(0, threat_intelligence)

         # Both threat databases are currently treated
        # as one combined threat-intelligence category.


    # -------------------------
    # FINAL TRUST QUOTIENT
    # -------------------------

    score = (
        threat_intelligence * 0.35
        + domain_reputation * 0.25
        + security_posture * 0.25
        + network_signals * 0.15
    )

    score = round(score)

    return {
        "trust_score": score,
        "threat_intelligence": threat_intelligence,
        "domain_reputation": domain_reputation,
        "security_posture": security_posture,
        "network_signals": network_signals,
        "reasons": reasons
    }