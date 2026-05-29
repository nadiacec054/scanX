from flask import Flask, render_template, request
import requests
from datetime import datetime
from urllib.parse import urlparse

app = Flask(__name__)


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
        if r["severity"] == "High" and r["status"] != "Safe":
            score += 25
        elif r["severity"] == "Medium" and r["status"] != "Safe":
            score += 15
        elif r["severity"] == "Low" and r["status"] != "Safe":
            score += 5

    return min(score, 100)


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

        # HTTPS Check
        final_url = response.url

        if final_url.startswith("https://"):
            add_result(
                results,
                "HTTPS Check",
                "Safe",
                "High",
                "Website is using HTTPS.",
                "No action needed."
            )
        else:
            add_result(
                results,
                "HTTPS Check",
                "Warning",
                "High",
                "Website is not using HTTPS.",
                "Use HTTPS with a valid SSL certificate."
            )

        # Security Header Checks
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
                add_result(
                    results,
                    header,
                    "Safe",
                    details["severity"],
                    f"{header} is present.",
                    "No action needed."
                )
            else:
                add_result(
                    results,
                    header,
                    "Warning",
                    details["severity"],
                    details["message"],
                    details["fix"]
                )

        # Cookie Security Checks
        if response.cookies:
            for cookie in response.cookies:
                if cookie.secure:
                    add_result(
                        results,
                        f"Cookie Secure Flag: {cookie.name}",
                        "Safe",
                        "Medium",
                        "Cookie has Secure flag enabled.",
                        "No action needed."
                    )
                else:
                    add_result(
                        results,
                        f"Cookie Secure Flag: {cookie.name}",
                        "Warning",
                        "Medium",
                        "Cookie is missing Secure flag.",
                        "Set Secure flag so cookie is only sent over HTTPS."
                    )

                if cookie.has_nonstandard_attr("HttpOnly"):
                    add_result(
                        results,
                        f"Cookie HttpOnly Flag: {cookie.name}",
                        "Safe",
                        "Medium",
                        "Cookie has HttpOnly flag enabled.",
                        "No action needed."
                    )
                else:
                    add_result(
                        results,
                        f"Cookie HttpOnly Flag: {cookie.name}",
                        "Warning",
                        "Medium",
                        "Cookie is missing HttpOnly flag.",
                        "Set HttpOnly to reduce JavaScript-based cookie theft risk."
                    )

                same_site = cookie.get_nonstandard_attr("SameSite")

                if same_site:
                    add_result(
                        results,
                        f"Cookie SameSite Flag: {cookie.name}",
                        "Safe",
                        "Low",
                        f"Cookie has SameSite={same_site}.",
                        "No action needed."
                    )
                else:
                    add_result(
                        results,
                        f"Cookie SameSite Flag: {cookie.name}",
                        "Warning",
                        "Low",
                        "Cookie is missing SameSite attribute.",
                        "Set SameSite=Lax or SameSite=Strict."
                    )
        else:
            add_result(
                results,
                "Cookie Check",
                "Info",
                "Low",
                "No cookies were found in the response.",
                "No action needed."
            )

        # Server Information Detection
        server = headers.get("Server", "Not disclosed")
        powered_by = headers.get("X-Powered-By", "Not disclosed")

        if server != "Not disclosed" or powered_by != "Not disclosed":
            add_result(
                results,
                "Server Information",
                "Info",
                "Low",
                f"Server: {server}, X-Powered-By: {powered_by}",
                "Hide unnecessary server/version information if exposed."
            )
        else:
            add_result(
                results,
                "Server Information",
                "Safe",
                "Low",
                "Server technology information is not disclosed.",
                "No action needed."
            )

        # Basic URL Info
        parsed_url = urlparse(final_url)

        add_result(
            results,
            "Domain Information",
            "Info",
            "Low",
            f"Scanned domain: {parsed_url.netloc}",
            "Informational result."
        )

        risk_score = calculate_risk_score(results)
        scan_time = datetime.now().strftime("%d-%m-%Y %H:%M:%S")

        return results, risk_score, scan_time, final_url

    except requests.exceptions.Timeout:
        add_result(
            results,
            "Connection Timeout",
            "Error",
            "High",
            "The website took too long to respond.",
            "Check if the URL is correct or try again later."
        )

    except requests.exceptions.ConnectionError:
        add_result(
            results,
            "Connection Error",
            "Error",
            "High",
            "Could not connect to the website.",
            "Check the URL or internet connection."
        )

    except requests.exceptions.InvalidURL:
        add_result(
            results,
            "Invalid URL",
            "Error",
            "High",
            "The entered URL is invalid.",
            "Enter a valid URL like https://example.com."
        )

    except Exception as e:
        add_result(
            results,
            "Unexpected Error",
            "Error",
            "High",
            str(e),
            "Try again with a valid website URL."
        )

    risk_score = calculate_risk_score(results)
    scan_time = datetime.now().strftime("%d-%m-%Y %H:%M:%S")

    return results, risk_score, scan_time, url


@app.route("/", methods=["GET", "POST"])
def index():
    results = None
    risk_score = None
    scan_time = None
    scanned_url = None

    if request.method == "POST":
        url = request.form.get("url")

        if url:
            results, risk_score, scan_time, scanned_url = check_security(url)

    return render_template(
        "index.html",
        results=results,
        risk_score=risk_score,
        scan_time=scan_time,
        scanned_url=scanned_url
    )


if __name__ == "__main__":
    app.run(debug=True)
