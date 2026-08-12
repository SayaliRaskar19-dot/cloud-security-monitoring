# Cloud Security Monitoring System

A simple cloud security monitoring system that detects suspicious activities from security logs, records security incidents, and performs automated responses such as IP blocking.

## Project Overview

The system analyzes security log data and identifies common security threats such as:

- Brute Force Attacks
- Suspicious IP Activity

When a threat is detected, the system creates an alert, blocks the suspicious IP, and records the incident in an incident log.

A Flask-based web dashboard is used to monitor the detected incidents and security status.

## Features

- Security log monitoring
- Brute force attack detection
- Suspicious IP detection
- Automated IP blocking
- Security alert generation
- Incident logging
- Incident status tracking
- Security monitoring dashboard
- Login authentication
- Statistics for incidents and severity
- Blocked IP monitoring
- Threat detection page
- Reports and settings pages

## Technologies Used

- Python
- Flask
- HTML
- CSS
- JavaScript
- CSV
- Git & GitHub

## Detection Methods

### 1. Brute Force Detection

The system counts failed login attempts for each IP address.

If an IP address has 5 or more failed login attempts, it is treated as a brute force attack.

```text
Failed Attempts >= 5
        ↓
Brute Force Detected
        ↓
HIGH Severity
        ↓
IP Blocked
        ↓
Incident Recorded
2. Suspicious IP Detection

The system maintains a list of suspicious IP addresses.

If an IP from the security logs matches this list, suspicious IP activity is detected.

Security Log
     ↓
Check IP
     ↓
Suspicious IP List
     ↓
Threat Detected
     ↓
IP Blocked
     ↓
Incident Recorded
Automated Response

When a threat is detected, the system performs the following actions:

Detects the security event
Generates a security alert
Blocks the suspicious IP
Saves the incident
Displays the incident on the dashboard
Dashboard

The web dashboard displays:

Total incidents
High severity incidents
Blocked IPs
Resolved incidents
Attack activity
Security status
Recent security incidents
Project Structure
cloud-security-monitoring/
│
├── app.py
│
├── detection/
│   ├── detection.py
│   └── suspicious_ips.py
│
├── incidents/
│   └── incident_log.csv
│
├── logs/
│   └── security_logs.csv
│
├── response/
│   └── response.py
│
├── templates/
│   ├── login.html
│   ├── dashboard.html
│   ├── incidents.html
│   ├── blocked_ips.html
│   ├── threat_detection.html
│   ├── reports.html
│   └── settings.html
│
└── .gitignore
How to Run
1. Clone the repository
git clone https://github.com/SayaliRaskar19-dot/cloud-security-monitoring.git
2. Open the project
cd cloud-security-monitoring
3. Install Flask
pip install flask
4. Run the application
python app.py
5. Open the dashboard

Open the following address in your browser:

http://127.0.0.1:5000/login
Demo Login
Username: admin
Password: admin123
Sample Security Events

The project currently demonstrates detection of:

Attack Type	Severity	Response
Brute Force Attack	HIGH	IP Blocked
Suspicious IP Activity	HIGH	IP Blocked
Purpose

The main purpose of this project is to demonstrate how security logs can be analyzed to identify suspicious activities and how basic automated responses can be performed using Python.

Future Improvements
Database integration
Real-time log monitoring
Email notifications
More attack detection rules
User role management
Cloud platform integration
Improved security authentication
