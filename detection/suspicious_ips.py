# Demo suspicious IP list
SUSPICIOUS_IPS = {
    "192.168.1.50",
    "10.0.0.99",
    "172.16.0.25"
}


def is_suspicious_ip(ip):
    return ip in SUSPICIOUS_IPS