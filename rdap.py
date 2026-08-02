import requests
from datetime import datetime


def get_registration_date(domain):
    url = f"https://rdap.org/domain/{domain}"

    try:
        response = requests.get(url, timeout=10)

        if response.status_code != 200:
            print(f"RDAP lookup failed: HTTP {response.status_code}")
            return None

        data = response.json()

    except requests.RequestException as e:
        print(f"RDAP request failed: {e}")
        return None

    except ValueError:
        print("RDAP returned an invalid JSON response.")
        return None

    for event in data.get("events", []):
        if event.get("eventAction") == "registration":
            registration_date = event.get("eventDate")

            try:
                return datetime.strptime(
                    registration_date,
                    "%Y-%m-%dT%H:%M:%SZ"
                )
            except (TypeError, ValueError):
                return None

    return None