def calculate_score(
    domain_age,
    ssl_valid,
    dns_valid,
    security_headers,
    threat_results,
    https_worked,
    url_signals,
    status_code
):

    reasons = []
    confidence_reasons = []

    # -------------------------
    # DEFAULT VALUES
    # -------------------------

    if security_headers is None:
        security_headers = {}

    if threat_results is None:
        threat_results = {}

    if url_signals is None:
        url_signals = []

    threat_intelligence = 0
    domain_reputation = 0
    security_posture = 0
    network_signals = 0

    # =====================================================
    # DOMAIN REPUTATION
    # =====================================================

    if domain_age is None:

        domain_reputation = 55

        reasons.append(
            "Domain registration date is unavailable; "
            "domain reputation is reduced due to limited evidence."
        )

    elif domain_age < 7:

        domain_reputation = 0

        reasons.append(
            "Domain is less than 7 days old."
        )

    elif domain_age <= 30:

        domain_reputation = 25

        reasons.append(
            "Domain is less than 30 days old."
        )

    elif domain_age <= 180:

        domain_reputation = 50

        reasons.append(
            "Domain is between 31 and 180 days old."
        )

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

    # =====================================================
    # SECURITY POSTURE
    # =====================================================

    if ssl_valid is True:

        security_posture += 40

        reasons.append(
            "SSL certificate is valid."
        )

    elif ssl_valid is False:

        reasons.append(
            "SSL certificate is invalid or expired."
        )

    else:

        reasons.append(
            "SSL certificate status could not be determined."
        )

    # HTTPS

    if https_worked is True:

        security_posture += 20

        reasons.append(
            "HTTPS is accessible."
        )

    elif https_worked is False:

        reasons.append(
            "HTTPS is unavailable; HTTP fallback was used."
        )

    else:

        reasons.append(
            "HTTPS accessibility could not be determined."
        )

    # HSTS

    if security_headers.get("hsts"):

        security_posture += 15

        reasons.append(
            "HSTS is present."
        )

    # CSP

    if security_headers.get("csp"):

        security_posture += 15

        reasons.append(
            "Content Security Policy is present."
        )

    # X-Content-Type-Options

    if security_headers.get(
        "x_content_type_options"
    ):

        security_posture += 5

        reasons.append(
            "X-Content-Type-Options is present."
        )

    # X-Frame-Options

    if security_headers.get(
        "x_frame_options"
    ):

        security_posture += 5

        reasons.append(
            "X-Frame-Options is present."
        )

    # CSP Report Only

    if security_headers.get(
        "csp_report_only"
    ):

        reasons.append(
            "Content Security Policy is in report-only mode."
        )

    security_posture = min(
        security_posture,
        100
    )

    # =====================================================
    # NETWORK SIGNALS
    # =====================================================

    if dns_valid is True:

        network_signals += 70

        reasons.append(
            "Domain resolves successfully through DNS."
        )

    elif dns_valid is False:

        reasons.append(
            "Domain could not be resolved through DNS."
        )

    else:

        reasons.append(
            "DNS resolution status could not be determined."
        )

    # -------------------------
    # URL INTELLIGENCE
    # -------------------------

    url_score = 30

    for signal in url_signals:

        severity = signal.get(
            "severity",
            "low"
        )

        if severity == "low":

            url_score -= 3

        elif severity == "medium":

            url_score -= 10

        elif severity == "high":

            url_score -= 20

        message = signal.get(
            "message",
            "Suspicious URL characteristic detected."
        )

        reasons.append(
            f"URL signal: {message}"
        )

    url_score = max(
        0,
        url_score
    )

    network_signals += url_score

    network_signals = min(
        network_signals,
        100)

    # =====================================================
    # THREAT INTELLIGENCE
    # =====================================================

    threat_intelligence = 0

    google_result = threat_results.get("google_safe_browsing")

    openphish_result = threat_results.get("openphish")

    # -------------------------
    # GOOGLE SAFE BROWSING
    # -------------------------

    if google_result is True:

        reasons.append("Google Safe Browsing detected a threat.")

    elif google_result is False:

        threat_intelligence += 50

        reasons.append("Google Safe Browsing found no known threat.")

    else:

        reasons.append("Google Safe Browsing could not be checked.")

    # -------------------------
    # OPENPHISH
    # -------------------------

    if openphish_result is True:

        reasons.append("OpenPhish detected a known phishing URL.")

    elif openphish_result is False:

        threat_intelligence += 50

        reasons.append("OpenPhish found no known phishing match.")

    else:

        reasons.append("OpenPhish could not be checked.")

    threat_intelligence = max(
        0,
        min(
        threat_intelligence,
        100
        ))

    # =====================================================
    # FINAL TRUST QUOTIENT
    # =====================================================

    score = (

        threat_intelligence * 0.35

        + domain_reputation * 0.25

        + security_posture * 0.25

        + network_signals * 0.15

    )

    score = round(score)

    score = max(
        0,
        min(
            score,
            100
        )
    )

    # =====================================================
    # CONFIDENCE
    # =====================================================

    confidence_score = 0

    # Domain age

    if domain_age is not None:

        confidence_score += 2

    else:

        confidence_reasons.append(
            "Domain registration age could not be verified."
        )

    # SSL

    if ssl_valid is not None:

        confidence_score += 2

    else:

        confidence_reasons.append(
            "SSL certificate status could not be verified."
        )

    # DNS

    if dns_valid is not None:

        confidence_score += 2

    else:

        confidence_reasons.append(
            "DNS resolution status could not be verified."
        )

    # Google Safe Browsing

    if google_result is not None:

        confidence_score += 1

    else:

        confidence_reasons.append(
            "Google Safe Browsing could not be checked."
        )

    # OpenPhish

    if openphish_result is not None:

        confidence_score += 1

    else:

        confidence_reasons.append(
            "OpenPhish could not be checked."
        )

    # HTTPS

    if https_worked is not None:

        confidence_score += 1

    else:

        confidence_reasons.append(
            "HTTPS accessibility could not be determined."
        )

    # URL analysis

    if url_signals is not None:

        confidence_score += 1

    else:

        confidence_reasons.append(
            "URL structure and redirect analysis "
            "could not be completed."
        )

    # HTTP Status

    if status_code is not None:

            confidence_score += 1

    else:

        confidence_reasons.append(
        "HTTP response status could not be determined."
        )

    # -------------------------
    # CONFIDENCE LEVEL
    # -------------------------

    if confidence_score >= 10:

        confidence = "HIGH"

    elif confidence_score >= 7:

        confidence = "MEDIUM"

    else:

        confidence = "LOW"

    # =====================================================
    # RESULT
    # =====================================================

    return {

        "trust_score": score,

        "threat_intelligence":
            threat_intelligence,

        "domain_reputation":
            domain_reputation,

        "security_posture":
            security_posture,

        "network_signals":
            network_signals,

        "confidence":
            confidence,

        "confidence_reasons":
            confidence_reasons,

        "reasons":
            reasons
    }