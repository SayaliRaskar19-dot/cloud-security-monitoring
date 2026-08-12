import csv
from datetime import datetime

from response.response import block_ip, create_alert
from detection.suspicious_ips import is_suspicious_ip


INCIDENT_FILE = "incidents/incident_log.csv"
LOG_FILE = "logs/security_logs.csv"


def get_next_incident_id():
    try:
        with open(INCIDENT_FILE, "r", newline="") as file:
            reader = csv.DictReader(file)
            incidents = list(reader)

            return f"INC{len(incidents) + 1:03d}"

    except FileNotFoundError:
        return "INC001"


def incident_exists(ip, attack_type):
    try:
        with open(INCIDENT_FILE, "r", newline="") as file:
            reader = csv.DictReader(file)

            for incident in reader:
                if (
                    incident["ip_address"] == ip
                    and incident["attack_type"] == attack_type
                ):
                    return True

    except FileNotFoundError:
        return False

    return False


def save_incident(ip, attack_type, attempts, severity, action, status):

    incident_id = get_next_incident_id()

    with open(INCIDENT_FILE, "a", newline="") as file:

        writer = csv.writer(file)

        if file.tell() == 0:
            writer.writerow([
                "incident_id",
                "timestamp",
                "ip_address",
                "attack_type",
                "failed_attempts",
                "severity",
                "action",
                "status"
            ])

        writer.writerow([
            incident_id,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ip,
            attack_type,
            attempts,
            severity,
            action,
            status
        ])

    print(f"📝 Incident {incident_id} recorded.")


def run_detection():

    failed_attempts = {}

    # ==========================================
    # READ SECURITY LOGS
    # ==========================================

    with open(LOG_FILE, "r", newline="") as file:

        logs = csv.DictReader(file)

        for log in logs:

            ip = log["ip_address"]

            # ==========================================
            # 1. SUSPICIOUS IP DETECTION
            # ==========================================

            if is_suspicious_ip(ip):

                attack = "Suspicious IP Activity"

                if not incident_exists(ip, attack):

                    severity = "HIGH"
                    action = "IP Blocked"
                    status = "RESOLVED"

                    print()
                    print("🚨 SUSPICIOUS IP DETECTED")
                    print(f"IP: {ip}")
                    print(f"Severity: {severity}")

                    create_alert(ip, severity)
                    block_ip(ip)

                    save_incident(
                        ip,
                        attack,
                        0,
                        severity,
                        action,
                        status
                    )

            # ==========================================
            # 2. FAILED LOGIN COUNT
            # ==========================================

            if log["status"] == "FAILED":

                if ip not in failed_attempts:
                    failed_attempts[ip] = 0

                failed_attempts[ip] += 1

    # ==========================================
    # 3. BRUTE FORCE DETECTION
    # ==========================================

    for ip, count in failed_attempts.items():

        if count >= 5:

            attack = "Brute Force Attack"

            if not incident_exists(ip, attack):

                severity = "HIGH"
                action = "IP Blocked"
                status = "RESOLVED"

                print()
                print("🚨 BRUTE FORCE ATTACK DETECTED")
                print(f"IP: {ip}")
                print(f"Failed Attempts: {count}")
                print(f"Severity: {severity}")

                create_alert(ip, severity)
                block_ip(ip)

                save_incident(
                    ip,
                    attack,
                    count,
                    severity,
                    action,
                    status
                )


if __name__ == "__main__":
    run_detection()