from flask import Flask, render_template, request
from scanner import run_scan

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def home():
    results = None

    if request.method == "POST":
        url = request.form["url"]
        results = run_scan(url)

    return render_template("index.html", results=results)

if __name__ == "__main__":
    app.run(debug=True)
