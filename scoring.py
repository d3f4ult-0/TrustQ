def calculate_score(
    domain_age,
    ssl_valid,
    dns_valid,
    security_headers,
    threat_results,
    https_worked,
    url_signals
):

    reasons = []
    confidence_points = 0
    confidence_reasons = []

    threat_intelligence = 0
    domain_reputation = 0
    security_posture = 0
    network_signals = 0

    # -------------------------
    # DOMAIN REPUTATION
    # -------------------------

    if domain_age is None:
        domain_reputation = 80
        reasons.append(
            "Domain registration date is unavailable; "
            "domain reputation is reduced due to limited evidence."
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
        reasons.append(
            "Domain is between 181 days and 1 year old."
        )

    elif domain_age <= 1095:
        domain_reputation = 85
        reasons.append(
            "Domain is between 1 and 3 years old."
        )

    else:
        domain_reputation = 100
        reasons.append(
            "Domain is more than 3 years old."
        )

    # Confidence: Domain Reputation

    if domain_age is not None:
        confidence_points += 2
    else:
        confidence_reasons.append(
            "Domain registration date was unavailable."
        )

    # -------------------------
    # SECURITY POSTURE
    # -------------------------

    if ssl_valid:
        security_posture += 40
        reasons.append("SSL certificate is valid.")
    else:
        reasons.append(
            "SSL certificate is invalid or expired."
        )

    if https_worked:
        security_posture += 20
        reasons.append("HTTPS is accessible.")
    else:
        reasons.append(
            "HTTPS is unavailable; HTTP fallback was used."
        )

    if security_headers["hsts"]:
        security_posture += 15
        reasons.append("HSTS is present.")

    if security_headers["csp"]:
        security_posture += 15
        reasons.append(
            "Content Security Policy is present."
        )

    if security_headers["x_content_type_options"]:
        security_posture += 5
        reasons.append(
            "X-Content-Type-Options is present."
        )

    if security_headers["x_frame_options"]:
        security_posture += 5
        reasons.append(
            "X-Frame-Options is present."
        )

    if security_headers["csp_report_only"]:
        reasons.append(
            "Content Security Policy is in report-only mode."
        )

    # Confidence: SSL

    if ssl_valid is not None:
        confidence_points += 2
    else:
        confidence_reasons.append(
            "SSL status could not be determined."
        )

    # -------------------------
    # NETWORK SIGNALS
    # -------------------------

    if dns_valid:
        network_signals += 70
        reasons.append(
            "Domain resolves successfully through DNS."
        )
    else:
        reasons.append(
            "Domain could not be resolved through DNS. "
            "This may be caused by DNS failure or "
            "network-level filtering."
        )

    # Confidence: DNS

    if dns_valid is not None:
        confidence_points += 2
    else:
        confidence_reasons.append(
            "DNS status could not be determined."
        )

    # URL Intelligence

    url_score = 30

    for signal in url_signals:

        if signal["severity"] == "low":
            url_score -= 3

        elif signal["severity"] == "medium":
            url_score -= 10

        elif signal["severity"] == "high":
            url_score -= 20

        reasons.append(
            f"URL signal: {signal['message']}"
        )

    url_score = max(0, url_score)

    network_signals = 70 + url_score
    network_signals = min(network_signals, 100)

    # -------------------------
    # THREAT INTELLIGENCE
    # -------------------------

    threat_intelligence = 100

    google_result = threat_results.get("google_safe_browsing")
    openphish_result = threat_results.get("openphish")


# Google Safe Browsing

    if google_result is True:
        threat_intelligence -= 50
        reasons.append(
        "Google Safe Browsing detected a threat."
        )

    elif google_result is False:
        reasons.append(
            "Google Safe Browsing found no known threat."
        )

    else:
        reasons.append(
        "Google Safe Browsing could not be checked."
        )


    # OpenPhish

    if openphish_result is True:
        threat_intelligence -= 50
        reasons.append(
        "OpenPhish detected a known phishing URL."
        )

    elif openphish_result is False:
        reasons.append(
        "OpenPhish found no known phishing match."
        )

    else:
        reasons.append(
        "OpenPhish could not be checked."
        )


    # Keep score within valid range

    threat_intelligence = max(
    0,
    threat_intelligence
)


    # -------------------------
    # CONFIDENCE: THREAT INTEL
    # -------------------------

    if (
        google_result is not None
        and openphish_result is not None
    ):
        confidence_points += 2

    else:
        confidence_reasons.append(
        "One or more threat-intelligence sources "
        "could not be checked."
    )

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

    # -------------------------
    # CONFIDENCE
    # -------------------------

    confidence_score = 0

    if domain_age is not None:  
        confidence_score += 2
    else:   
        confidence_reasons.append(
        "Domain registration age could not be verified."
    )

    if ssl_valid is not None:   
        confidence_score += 2
    else:   
        confidence_reasons.append(
        "SSL certificate status could not be verified."
    )

    if dns_valid is not None:   
        confidence_score += 2
    else:   
        confidence_reasons.append(
        "DNS resolution status could not be verified."
    )

    if google_result is not None:   
        confidence_score += 1
    else:   
        confidence_reasons.append(
        "Google Safe Browsing could not be checked."
    )

    if openphish_result is not None:
        confidence_score += 1
    else:
        confidence_reasons.append(
        "OpenPhish could not be checked."
    )

    if https_worked is not None:
        confidence_score += 1
    else:
        confidence_reasons.append(
        "HTTPS accessibility could not be determined."
    )

    if url_signals is not None: 
        confidence_score += 1
    else:   
        confidence_reasons.append(
        "URL structure and redirect analysis could not be completed."
    )

    if confidence_score >= 9:
        confidence = "HIGH"

    elif confidence_score >= 6:
        confidence = "MEDIUM"

    else:
        confidence = "LOW"

    # -------------------------
    # RESULT
    # -------------------------

    return {
        "trust_score": score,
        "threat_intelligence": threat_intelligence,
        "domain_reputation": domain_reputation,
        "security_posture": security_posture,
        "network_signals": network_signals,
        "confidence": confidence,
        "confidence_reasons": confidence_reasons,
        "reasons": reasons
    }