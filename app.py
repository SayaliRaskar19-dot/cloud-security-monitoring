from flask import Flask, jsonify, render_template, request, redirect, session, url_for
import csv

from detection.detection import run_detection


app = Flask(__name__)

app.secret_key = "cloud-security-demo-secret"


# ---------------------------------------
# READ INCIDENTS
# ---------------------------------------

def read_incidents():

    incidents = []

    with open("incidents/incident_log.csv", "r") as file:

        reader = csv.DictReader(file)

        for row in reader:
            incidents.append(row)

    return incidents


# ---------------------------------------
# LOGIN
# ---------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        # Demo credentials
        if username == "admin" and password == "admin123":

            session["logged_in"] = True
            session["username"] = username

            return redirect(url_for("dashboard"))

        else:

            return render_template(
                "login.html",
                error="Invalid username or password"
            )

    return render_template("login.html")


# ---------------------------------------
# DASHBOARD
# ---------------------------------------

@app.route("/")
def dashboard():

    if not session.get("logged_in"):

        return redirect(url_for("login"))

    run_detection()

    return render_template(
        "dashboard.html",
        username=session.get("username")
    )
@app.route("/blocked-ips")
def blocked_ips():

    if not session.get("logged_in"):
        return redirect(url_for("login"))

    return render_template(
        "blocked_ips.html",
        username=session.get("username")
    )


# ---------------------------------------
# INCIDENT API
# ---------------------------------------

@app.route("/api/incidents")
def get_incidents():

    if not session.get("logged_in"):
        return jsonify({"error": "Unauthorized"}), 401

    incidents = read_incidents()

    return jsonify(incidents)


# ---------------------------------------
# STATISTICS API
# ---------------------------------------

@app.route("/api/stats")
def get_stats():

    if not session.get("logged_in"):
        return jsonify({"error": "Unauthorized"}), 401

    incidents = read_incidents()

    total_incidents = len(incidents)

    high_severity = sum(
        1
        for incident in incidents
        if incident["severity"] == "HIGH"
    )

    resolved = sum(
        1
        for incident in incidents
        if incident["status"] == "RESOLVED"
    )

    return jsonify({

        "total_incidents": total_incidents,

        "high_severity": high_severity,

        "resolved_incidents": resolved

    })
@app.route("/threat-detection")
def threat_detection():

    if not session.get("logged_in"):
        return redirect(url_for("login"))

    return render_template(
        "threat_detection.html",
        username=session.get("username")
    )
@app.route("/api/logs")
def get_logs():

    logs = []

    with open("logs/security_logs.csv", "r") as file:

        reader = csv.DictReader(file)

        for row in reader:
            logs.append(row)

    return jsonify(logs)
# ---------------------------------------
# REPORTS
# ---------------------------------------

@app.route("/reports")
def reports():

    if not session.get("logged_in"):
        return redirect(url_for("login"))

    incidents = read_incidents()

    return render_template(
        "reports.html",
        incidents=incidents,
        username=session.get("username")
    )


# ---------------------------------------
# SETTINGS
# ---------------------------------------

@app.route("/settings")
def settings():

    if not session.get("logged_in"):
        return redirect(url_for("login"))

    return render_template(
        "settings.html",
        username=session.get("username")
    )
@app.route("/incidents")
def incidents_page():

    if not session.get("logged_in"):
        return redirect(url_for("login"))

    return render_template(
        "incidents.html",
        username=session.get("username")
    )



# ---------------------------------------
# LOGOUT
# ---------------------------------------

@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("login"))


# ---------------------------------------
# START SERVER
# ---------------------------------------

if __name__ == "__main__":

    app.run(debug=True)