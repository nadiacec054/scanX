WEB VULNERABILITY SCANNER


overview
The Web Vulnerability Scanner is a Python-based security tool designed to automatically inspect web applications for common vulnerabilities. It combines crawling, payload-based testing, and report generation to identify issues such as SQL Injection, Cross-Site Scripting, and sensitive file exposure.
The project also includes a deliberately vulnerable Flask application, which is used as a controlled testing environment to verify scanner accuracy.

motivation:
Modern web applications often contain hidden attack surfaces such as exposed endpoints, weak input validation, and misconfigured files. This scanner aims to simplify the initial security testing process by automating vulnerability discovery and presenting the results in a clear HTML report.

core objectives:
- Automatically discover internal web pages through recursive crawling
- Detect user input fields and test them using security payloads
- Identify common OWASP-style vulnerabilities
- Generate a readable HTML report with severity-based classification
- Validate results using a custom vulnerable Flask application

workflow
```mermaid
flowchart TD
    A[Start Scanner] --> B[Enter Target URL]
    B --> C[Normalize and Validate URL]
    C --> D[Recursive Web Crawler]
    D --> E[Collect Internal Links]
    D --> F[Extract Forms and Input Fields]

    E --> G[Security Testing Engine]
    F --> G

    G --> H[SQL Injection Payload Testing]
    G --> I[XSS Payload Testing]
    G --> J[Sensitive File Exposure Checks]

    H --> K[Analyze Server Response]
    I --> K
    J --> K

    K --> L{Vulnerability Found?}
    L -->|Yes| M[Store Finding with Severity]
    L -->|No| N[Continue Scanning]

    M --> O[Generate HTML Report]
    N --> O
    O --> P[End]
