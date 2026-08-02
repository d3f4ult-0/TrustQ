import socket


def check_dns(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        return ip_address, True

    except socket.gaierror:
        return None, False