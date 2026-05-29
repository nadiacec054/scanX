from flask import Flask, render_template, request, send_file
import requests
from datetime import datetime
from urllib.parse import urlparse
import uuid
import os

from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie


app = Flask(__name__)

scan_store = {}

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORT_DIR = os.path.join(BASE_DIR, "reports")
os.makedirs(REPORT_DIR, exist_ok=True)


def normalize_url(url):
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    return url


def add_result(results, name, status, severity, message, fix):
    results.append({
        "name": name,
        "status": status,
        "severity": severity,
        "message": message,
        "fix": fix
    })


def calculate_risk_score(results):
    score = 0

    for r in results:
        if r["status"] in ["Warning", "Error"]:
            if r["severity"] == "High":
                score += 25
            elif r["severity"] == "Medium":
                score += 15
            elif r["severity"] == "Low":
                score += 5

    return min(score, 100)


def get_severity_counts(results):
    counts = {
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Info": 0
    }

    for r in results:
        severity = r["severity"]
        if severity in counts:
            counts[severity] += 1

    return counts


def create_pdf_pie_chart(counts):
    drawing = Drawing(320, 240)

    labels = []
    values = []
    slice_colors = []

    color_map = {
        "High": colors.red,
        "Medium": colors.orange,
        "Low": colors.green,
        "Info": colors.blue
    }

    for severity in ["High", "Medium", "Low", "Info"]:
        if counts[severity] > 0:
            labels.append(severity)
            values.append(counts[severity])
            slice_colors.append(color_map[severity])

    if not values:
        labels = ["No Findings"]
        values = [1]
        slice_colors = [colors.lightgrey]

    pie = Pie()
    pie.x = 75
    pie.y = 25
    pie.width = 170
    pie.height = 170
    pie.data = values
    pie.labels = labels
    pie.sideLabels = True

    for i, c in enumerate(slice_colors):
        pie.slices[i].fillColor = c

    drawing.add(pie)
    return drawing


def check_security(url):
    results = []

    try:
        url = normalize_url(url)

        response = requests.get(
            url,
            timeout=8,
            allow_redirects=True,
            headers={"User-Agent": "ScanX-Security-Scanner"}
        )

        headers = response.headers
        final_url = response.url

        if final_url.startswith("https://"):
            add_result(results, "HTTPS Check", "Safe", "Info", "Website is using HTTPS.", "No action needed.")
        else:
            add_result(results, "HTTPS Check", "Warning", "High", "Website is not using HTTPS.", "Use HTTPS with a valid SSL certificate.")

        security_headers = {
            "Content-Security-Policy": {
                "severity": "High",
                "message": "Content-Security-Policy header is missing. This can increase XSS risk.",
                "fix": "Add a strong Content-Security-Policy header."
            },
            "Strict-Transport-Security": {
                "severity": "High",
                "message": "Strict-Transport-Security header is missing.",
                "fix": "Add HSTS to force browsers to use HTTPS."
            },
            "X-Frame-Options": {
                "severity": "Medium",
                "message": "X-Frame-Options header is missing. This can allow clickjacking.",
                "fix": "Set X-Frame-Options to DENY or SAMEORIGIN."
            },
            "X-Content-Type-Options": {
                "severity": "Medium",
                "message": "X-Content-Type-Options header is missing.",
                "fix": "Set X-Content-Type-Options to nosniff."
            },
            "Referrer-Policy": {
                "severity": "Low",
                "message": "Referrer-Policy header is missing.",
                "fix": "Set Referrer-Policy to strict-origin-when-cross-origin."
            },
            "Permissions-Policy": {
                "severity": "Low",
                "message": "Permissions-Policy header is missing.",
                "fix": "Restrict browser features using Permissions-Policy."
            }
        }

        for header, details in security_headers.items():
            if header in headers:
                add_result(results, header, "Safe", "Info", f"{header} is present.", "No action needed.")
            else:
                add_result(results, header, "Warning", details["severity"], details["message"], details["fix"])

        if response.cookies:
            for cookie in response.cookies:
                if cookie.secure:
                    add_result(results, f"Cookie Secure Flag: {cookie.name}", "Safe", "Info", "Cookie has Secure flag enabled.", "No action needed.")
                else:
                    add_result(results, f"Cookie Secure Flag: {cookie.name}", "Warning", "Medium", "Cookie is missing Secure flag.", "Set Secure flag so cookie is only sent over HTTPS.")

                if cookie.has_nonstandard_attr("HttpOnly"):
                    add_result(results, f"Cookie HttpOnly Flag: {cookie.name}", "Safe", "Info", "Cookie has HttpOnly flag enabled.", "No action needed.")
                else:
                    add_result(results, f"Cookie HttpOnly Flag: {cookie.name}", "Warning", "Medium", "Cookie is missing HttpOnly flag.", "Set HttpOnly to reduce JavaScript-based cookie theft risk.")

                same_site = cookie.get_nonstandard_attr("SameSite")

                if same_site:
                    add_result(results, f"Cookie SameSite Flag: {cookie.name}", "Safe", "Info", f"Cookie has SameSite={same_site}.", "No action needed.")
                else:
                    add_result(results, f"Cookie SameSite Flag: {cookie.name}", "Warning", "Low", "Cookie is missing SameSite attribute.", "Set SameSite=Lax or SameSite=Strict.")
        else:
            add_result(results, "Cookie Check", "Info", "Info", "No cookies were found in the response.", "No action needed.")

        server = headers.get("Server", "Not disclosed")
        powered_by = headers.get("X-Powered-By", "Not disclosed")

        if server != "Not disclosed" or powered_by != "Not disclosed":
            add_result(results, "Server Information", "Info", "Low", f"Server: {server}, X-Powered-By: {powered_by}", "Hide unnecessary server/version information if exposed.")
        else:
            add_result(results, "Server Information", "Safe", "Info", "Server technology information is not disclosed.", "No action needed.")

        parsed_url = urlparse(final_url)
        add_result(results, "Domain Information", "Info", "Info", f"Scanned domain: {parsed_url.netloc}", "Informational result.")

        risk_score = calculate_risk_score(results)
        scan_time = datetime.now().strftime("%d-%m-%Y %H:%M:%S")

        return results, risk_score, scan_time, final_url

    except Exception as e:
        add_result(results, "Scan Error", "Error", "High", str(e), "Check the URL and try again.")

        risk_score = calculate_risk_score(results)
        scan_time = datetime.now().strftime("%d-%m-%Y %H:%M:%S")

        return results, risk_score, scan_time, url


def generate_pdf_report(scan_id):
    scan_data = scan_store.get(scan_id)

    if not scan_data:
        return None

    results = scan_data["results"]
    risk_score = scan_data["risk_score"]
    scan_time = scan_data["scan_time"]
    scanned_url = scan_data["scanned_url"]
    counts = scan_data["counts"]

    pdf_path = os.path.join(REPORT_DIR, f"ScanX_Report_{scan_id}.pdf")

    doc = SimpleDocTemplate(pdf_path, pagesize=A4)
    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph("ScanX Security Report", styles["Title"]))
    story.append(Spacer(1, 12))

    story.append(Paragraph(f"<b>Target URL:</b> {scanned_url}", styles["Normal"]))
    story.append(Paragraph(f"<b>Scan Time:</b> {scan_time}", styles["Normal"]))
    story.append(Paragraph(f"<b>Risk Score:</b> {risk_score}/100", styles["Normal"]))
    story.append(Spacer(1, 20))

    story.append(Paragraph("Severity Summary", styles["Heading2"]))

    summary_data = [
        ["Severity", "Count"],
        ["High", counts["High"]],
        ["Medium", counts["Medium"]],
        ["Low", counts["Low"]],
        ["Info", counts["Info"]]
    ]

    summary_table = Table(summary_data)
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.darkblue),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 1, colors.black),
        ("PADDING", (0, 0), (-1, -1), 8)
    ]))

    story.append(summary_table)
    story.append(Spacer(1, 20))

    story.append(Paragraph("Findings Pie Chart", styles["Heading2"]))
    story.append(create_pdf_pie_chart(counts))
    story.append(Spacer(1, 20))

    story.append(Paragraph("Detailed Findings", styles["Heading2"]))

    for r in results:
        story.append(Paragraph(f"<b>{r['name']}</b>", styles["Heading3"]))
        story.append(Paragraph(f"<b>Status:</b> {r['status']}", styles["Normal"]))
        story.append(Paragraph(f"<b>Severity:</b> {r['severity']}", styles["Normal"]))
        story.append(Paragraph(f"<b>Details:</b> {r['message']}", styles["Normal"]))
        story.append(Paragraph(f"<b>Recommendation:</b> {r['fix']}", styles["Normal"]))
        story.append(Spacer(1, 12))

    doc.build(story)

    return pdf_path


@app.route("/", methods=["GET", "POST"])
def index():
    results = None
    risk_score = None
    scan_time = None
    scanned_url = None
    scan_id = None
    counts = None

    if request.method == "POST":
        url = request.form.get("url")

        if url:
            results, risk_score, scan_time, scanned_url = check_security(url)

            scan_id = str(uuid.uuid4())
            counts = get_severity_counts(results)

            scan_store[scan_id] = {
                "results": results,
                "risk_score": risk_score,
                "scan_time": scan_time,
                "scanned_url": scanned_url,
                "counts": counts
            }

    return render_template(
        "index.html",
        results=results,
        risk_score=risk_score,
        scan_time=scan_time,
        scanned_url=scanned_url,
        scan_id=scan_id,
        counts=counts
    )


@app.route("/download_report/<scan_id>")
def download_report(scan_id):
    pdf_path = generate_pdf_report(scan_id)

    if not pdf_path:
        return "Report not found", 404

    return send_file(pdf_path, as_attachment=True)


if __name__ == "__main__":
    app.run(debug=True)
