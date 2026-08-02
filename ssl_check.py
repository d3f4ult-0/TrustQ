import ssl
import socket
from datetime import datetime


def get_ssl_certificate(domain):
    context = ssl.create_default_context()

    with socket.create_connection((domain, 443)) as sock:
        with context.wrap_socket(sock, server_hostname=domain) as secure_sock:
            certificate = secure_sock.getpeercert()

    expiry = datetime.strptime(
        certificate["notAfter"],
        "%b %d %H:%M:%S %Y %Z"
    )

    today = datetime.now()

    if today > expiry:
        ssl_valid = False
    else:
        ssl_valid = True

    return certificate, expiry, ssl_valid