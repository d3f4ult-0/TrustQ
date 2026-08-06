import os
import requests
from dotenv import load_dotenv
from protobuf_defs import url_search_pb2

load_dotenv()


def check_openphish(url):
    feed_url = "https://openphish.com/feed.txt"

    try:
        response = requests.get(
            feed_url,
            timeout=10
        )

        response.raise_for_status()

        phishing_urls = response.text.splitlines()

        return url in phishing_urls

    except requests.RequestException:
        return None


def check_threat_intelligence(domain):
    results = {}

    api_key = os.getenv("GOOGLE_SAFE_BROWSING_KEY")

    # -------------------------
    # GOOGLE SAFE BROWSING
    # -------------------------

    if not api_key:
        results["google_safe_browsing"] = None

    else:
        url = "https://safebrowsing.googleapis.com/v5/urls:search"

        params = {
            "key": api_key,
            "urls": f"https://{domain}"
        }

        try:
            response = requests.get(
                url,
                params=params,
                headers={
                    "Accept": "application/json"
                },
                timeout=10
            )

            response.raise_for_status()

            search_response = url_search_pb2.SearchUrlsResponse()
            search_response.ParseFromString(response.content)

            if search_response.threats:
                results["google_safe_browsing"] = True
            else:
                results["google_safe_browsing"] = False

        except (
            requests.RequestException,
            ValueError
        ):
            results["google_safe_browsing"] = None

    # -------------------------
    # OPENPHISH
    # -------------------------

    target_url = f"https://{domain}"

    results["openphish"] = check_openphish(
        target_url
    )

    return results