import socket
import ssl
from datetime import datetime


def get_ssl_certificate(domain):
    context = ssl.create_default_context()

    try:
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(
                sock,
                server_hostname=domain
            ) as secure_sock:

                certificate = secure_sock.getpeercert()

                expiry_string = certificate.get("notAfter")

                if expiry_string:
                    expiry = datetime.strptime(
                        expiry_string,
                        "%b %d %H:%M:%S %Y %Z"
                    )
                else:
                    expiry = None

                return certificate, expiry, True

    except ssl.SSLCertVerificationError as error:
        return None, None, False

    except (socket.timeout, socket.error, ssl.SSLError):
        return None, None, False