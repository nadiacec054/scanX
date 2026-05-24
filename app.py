import requests

def check_security_headers(url):
    results = []

    try:
        response = requests.get(url, timeout=5)
        headers = response.headers

        security_headers = [
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Strict-Transport-Security"
        ]

        for header in security_headers:
            if header in headers:
                results.append({
                    "name": header,
                    "status": "Safe",
                    "message": f"{header} is present"
                })
            else:
                results.append({
                    "name": header,
                    "status": "Warning",
                    "message": f"{header} is missing"
                })

    except Exception as e:
        results.append({
            "name": "Connection Error",
            "status": "Error",
            "message": str(e)
        })

    return results


def check_xss(url):
    results = []

    payload = "<script>alert('xss')</script>"

    if "?" in url:
        test_url = url + "&q=" + payload
    else:
        test_url = url + "?q=" + payload

    try:
        response = requests.get(test_url, timeout=5)

        if payload in response.text:
            results.append({
                "name": "XSS Test",
                "status": "Vulnerable",
                "message": "Possible reflected XSS detected"
            })
        else:
            results.append({
                "name": "XSS Test",
                "status": "Safe",
                "message": "No reflected XSS detected"
            })

    except Exception as e:
        results.append({
            "name": "XSS Test",
            "status": "Error",
            "message": str(e)
        })

    return results


def run_scan(url):
    if not url.startswith("http"):
        url = "http://" + url

    results = []

    results.extend(check_security_headers(url))
    results.extend(check_xss(url))

    return results
