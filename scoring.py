def calculate_score(domain_age, ssl_valid, dns_valid, security_headers, threat_results):
    domain_score = 0
    ssl_score = 0
    dns_score = 0
    headers_score = 0
    threat_score = 0
    

    reasons = []

    #Domain Age
    if domain_age < 7:
        domain_score = 0
        reasons.append("Domain is less than 7 days old.")

    elif domain_age <= 30:
        domain_score = 5
        reasons.append("Domain is less than 30 days old.")

    elif domain_age <= 180:
        domain_score = 10
        reasons.append("Domain is between 31 and 180 days old.")

    elif domain_age <= 365:
        domain_score = 14
        reasons.append("Domain is between 181 days and 1 year old.")

    elif domain_age <= 1095:
        domain_score = 17
        reasons.append("Domain is between 1 and 3 years old.")

    else:
        domain_score = 20
        reasons.append("Domain is more than 3 years old.")

    #SSL
    if ssl_valid:
        ssl_score = 20
        reasons.append("SSL certificate is valid.")
    else:
        ssl_score = 0
        reasons.append("SSL certificate is invalid or expired.")

    #DNS
    if dns_valid:
        dns_score = 10
        reasons.append("Domain resolves successfully through DNS.")
    else:
        dns_score = 5
        reasons.append(
        "Domain could not be resolved through DNS. "
        "This may be caused by DNS failure or network-level filtering.")
        
    # Security Headers
    if security_headers["hsts"]:
        headers_score += 3
        reasons.append("HSTS is present.")

    if security_headers["csp"]:
        headers_score += 3
        reasons.append("Content Security Policy is present.")

    if security_headers["x_content_type_options"]:
        headers_score += 2
        reasons.append("X-Content-Type-Options is present.")

    if security_headers["x_frame_options"]:
        headers_score += 2
        reasons.append("X-Frame-Options is present.")

    if security_headers["csp_report_only"]:
        reasons.append("Content Security Policy is in report-only mode.")

    #Threat Intelligence
    if threat_results.get("google_safe_browsing"):
        reasons.append("Google Safe Browsing detected a threat.")
    else:
        threat_score += 20
        reasons.append("Google Safe Browsing found no known threat.")

    if threat_results.get("openphish"):
        reasons.append("OpenPhish detected a known phishing URL.")
    else:
        threat_score += 20
        reasons.append("OpenPhish found no known phishing match.")

         # Both threat databases are currently treated
        # as one combined threat-intelligence category.


    # -------------------------
    # FINAL SCORE
    # -------------------------


    score = domain_score + ssl_score + dns_score + headers_score + threat_score

     # Safety clamp.
    score = max(0, min(score, 100))
    return score, reasons