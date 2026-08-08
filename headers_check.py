import requests
import urllib3

urllib3.disable_warnings(
    urllib3.exceptions.InsecureRequestWarning
)


def check_security_headers(domain):
    url = f"https://{domain}"

    response = requests.get(url, timeout=10, verify=False)
    headers = response.headers

    security_headers = {
        "hsts": "Strict-Transport-Security" in headers,
        "csp": "Content-Security-Policy" in headers,
        "csp_report_only": "Content-Security-Policy-Report-Only" in headers,
        "x_content_type_options": "X-Content-Type-Options" in headers,
        "x_frame_options": "X-Frame-Options" in headers
    }

    return security_headers