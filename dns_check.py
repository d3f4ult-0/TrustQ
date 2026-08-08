import dns.resolver
import dns.exception


def check_dns(domain):
    try:
        answers = dns.resolver.resolve(
            domain,
            "A",
            lifetime=3
        )

        ip_address = answers[0].to_text()

        return ip_address, True

    except dns.resolver.NXDOMAIN:
        # Domain genuinely does not exist
        return None, False

    except (
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.exception.Timeout
    ):
        # DNS exists, but we couldn't obtain a usable answer
        return None, None

    except Exception:
        # Unknown resolver/network failure
        return None, None