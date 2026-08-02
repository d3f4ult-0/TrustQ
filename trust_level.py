def get_trust_level(score):

    if score >= 90:

        return {
            "label": "HIGH TRUST SIGNALS",
            "severity": "low",
            "description": (
                "Strong technical and threat-intelligence "
                "signals were detected."
            ),
            "guidance": [
                "Browsing appears reasonable based on available signals.",
                "No known threat match was detected.",
                "Still verify requests for sensitive information."
            ]
        }

    elif score >= 75:

        return {
            "label": "GENERALLY TRUSTWORTHY",
            "severity": "low",
            "description": (
                "The website shows generally positive "
                "trust signals, but no automated assessment "
                "can guarantee that a website is safe."
            ),
            "guidance": [
                "Normal browsing appears reasonable.",
                "Avoid sharing unnecessary sensitive information.",
                "Verify unexpected requests for credentials or payments."
            ]
        }

    elif score >= 60:

        return {
            "label": "USE CAUTION",
            "severity": "medium",
            "description": (
                "Some trust signals are present, but "
                "important indicators are missing or weak."
            ),
            "guidance": [
                "Browsing may be reasonable.",
                "Avoid entering passwords or credentials.",
                "Avoid sharing sensitive personal information.",
                "Avoid entering financial or payment information."
            ]
        }

    elif score >= 40:

        return {
            "label": "LOW TRUST SIGNALS",
            "severity": "high",
            "description": (
                "Several warning indicators were detected. "
                "The available evidence does not provide "
                "strong confidence in this website."
            ),
            "guidance": [
                "Do not enter passwords or credentials.",
                "Do not provide sensitive personal information.",
                "Do not enter financial or payment information.",
                "Consider leaving the website."
            ]
        }

    else:

        return {
            "label": "HIGH RISK SIGNALS",
            "severity": "critical",
            "description": (
                "Multiple significant warning indicators "
                "were detected."
            ),
            "guidance": [
                "Do not enter passwords or credentials.",
                "Do not provide sensitive personal information.",
                "Do not enter financial or payment information.",
                "Consider leaving the website."
            ]
        }