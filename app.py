from flask import Flask, render_template, request
import re
from urllib.parse import urlparse, parse_qs

app = Flask(__name__)


def is_valid_url(url):
    pattern = r"^https?://[^\s]+$"
    return re.match(pattern, url) is not None


def analyze_url(url):

    risk_score = 0
    reasons = []

    url_lower = url.lower()

    # Parse the URL
    try:
        parsed_url = urlparse(url_lower)
    except ValueError:
        parsed_url = None

    # --------------------------------------------------
    # Check 1: HTTPS
    # --------------------------------------------------

    if not url_lower.startswith("https://"):

        risk_score += 20

        reasons.append(
            "Website does not use HTTPS"
        )

    # --------------------------------------------------
    # Check 2: IP address instead of domain name
    # --------------------------------------------------

    ip_pattern = r"^https?://(\d{1,3}\.){3}\d{1,3}"

    if re.search(ip_pattern, url_lower):

        risk_score += 25

        reasons.append(
            "URL uses an IP address instead of a domain name"
        )

    # --------------------------------------------------
    # Check 3: Very long URL
    # --------------------------------------------------

    if len(url) > 100:

        risk_score += 15

        reasons.append(
            "URL is unusually long"
        )

    # --------------------------------------------------
    # Check 4: @ symbol
    # --------------------------------------------------

    if "@" in url:

        risk_score += 25

        reasons.append(
            "URL contains an @ symbol"
        )

    # --------------------------------------------------
    # Check 5: Suspicious keywords
    # --------------------------------------------------

    suspicious_words = [
        "login",
        "verify",
        "account",
        "free",
        "claim"
    ]

    found_words = []

    if parsed_url is not None:

        hostname_and_path = (
            (parsed_url.hostname or "")
            + parsed_url.path
        )

        for word in suspicious_words:

            if word in hostname_and_path:

                found_words.append(word)

    if found_words:

        risk_score += 20

        reasons.append(
            "Suspicious keywords found: "
            + ", ".join(found_words)
        )

    # --------------------------------------------------
    # Check 6: Suspicious domain words
    # --------------------------------------------------

    if parsed_url is not None:

        domain = parsed_url.hostname or ""

        suspicious_domain_words = [
            "secure",
            "account",
            "verify",
            "login",
            "update",
            "support",
            "confirmation"
        ]

        found_domain_words = []

        for word in suspicious_domain_words:

            if word in domain:

                found_domain_words.append(word)

        if found_domain_words:

            risk_score += 10

            reasons.append(
                "Suspicious words found in domain: "
                + ", ".join(found_domain_words)
            )

    # --------------------------------------------------
    # Check 7: Look-alike / typosquatting patterns
    # --------------------------------------------------

    if parsed_url is not None:

        domain = parsed_url.hostname or ""

        lookalike_patterns = {
            "g00gle": "google",
            "paypa1": "paypal",
            "micros0ft": "microsoft",
            "faceb00k": "facebook",
            "amaz0n": "amazon",
            "app1e": "apple"
        }

        found_lookalikes = []

        for suspicious_pattern, original_name in lookalike_patterns.items():

            if suspicious_pattern in domain:

                found_lookalikes.append(
                    suspicious_pattern + " resembles " + original_name
                )

        if found_lookalikes:

            risk_score += 25

            for lookalike in found_lookalikes:

                reasons.append(
                    "Possible look-alike domain detected: "
                    + lookalike
                )

    # --------------------------------------------------
    # Check 8: Too many subdomains
    # --------------------------------------------------

    try:

        if parsed_url is not None:

            domain = parsed_url.hostname or ""

            is_ip_address = re.match(
                r"^\d{1,3}(\.\d{1,3}){3}$",
                domain
            )

            if not is_ip_address:

                domain_parts = domain.split(".")

                if len(domain_parts) > 3:

                    risk_score += 15

                    reasons.append(
                        "URL contains an unusually large number "
                        "of subdomains"
                    )

    except ValueError:

        pass

    # --------------------------------------------------
    # Check 9: URL shortener
    # --------------------------------------------------

    shorteners = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "is.gd",
        "cutt.ly"
    ]

    for shortener in shorteners:

        if shortener in url_lower:

            risk_score += 15

            reasons.append(
                "URL uses a URL shortening service"
            )

            break

    # --------------------------------------------------
    # Check 10: Suspicious characters
    # --------------------------------------------------

    suspicious_characters = [
        "\\"
    ]

    found_character = False

    for character in suspicious_characters:

        if character in url:

            found_character = True

            break

    if found_character:

        risk_score += 10

        reasons.append(
            "URL contains unusual characters or patterns"
        )

    # --------------------------------------------------
    # Check 11: Non-standard port
    # --------------------------------------------------

    if parsed_url is not None:

        try:

            port = parsed_url.port

            if port is not None and port not in [80, 443]:

                risk_score += 10

                reasons.append(
                    f"URL uses a non-standard port: {port}"
                )

        except ValueError:

            risk_score += 10

            reasons.append(
                "URL contains an invalid port number"
            )

    # --------------------------------------------------
    # Check 12: Suspicious query parameters
    # --------------------------------------------------

    if parsed_url is not None:

        query = parsed_url.query.lower()

        suspicious_parameters = [
            "password",
            "passwd",
            "token",
            "auth",
            "verify",
            "redirect"
        ]

        found_parameters = []

        try:

            query_parameters = parse_qs(query).keys()

            for parameter in suspicious_parameters:

                if parameter in query_parameters:

                    found_parameters.append(parameter)

        except ValueError:

            pass

        if found_parameters:

            risk_score += 15

            reasons.append(
                "Suspicious query parameters found: "
                + ", ".join(found_parameters)
            )

    # --------------------------------------------------
    # Check 13: Excessive query length
    # --------------------------------------------------

    if parsed_url is not None:

        query = parsed_url.query

        if len(query) > 80:

            risk_score += 10

            reasons.append(
                "URL contains an unusually long query string"
            )

    # --------------------------------------------------
    # Keep score between 0 and 100
    # --------------------------------------------------

    risk_score = min(risk_score, 100)

    # --------------------------------------------------
    # Determine risk level
    # --------------------------------------------------

    if risk_score >= 60:

        risk_level = "High Risk"

    elif risk_score >= 30:

        risk_level = "Medium Risk"

    else:

        risk_level = "Low Risk"

    return risk_score, risk_level, reasons


# --------------------------------------------------
# Home page
# --------------------------------------------------

@app.route("/", methods=["GET", "POST"])
def home():

    result = None

    if request.method == "POST":

        url = request.form.get("url", "").strip()

        if not is_valid_url(url):

            result = {
                "url": url,
                "score": 0,
                "level": "Invalid URL",
                "reasons": [
                    "Please enter a valid URL starting with "
                    "http:// or https://"
                ]
            }

        else:

            risk_score, risk_level, reasons = analyze_url(url)

            result = {
                "url": url,
                "score": risk_score,
                "level": risk_level,
                "reasons": reasons
            }

    return render_template(
        "index.html",
        result=result
    )


# --------------------------------------------------
# Run Flask application
# --------------------------------------------------

if __name__ == "__main__":

    app.run(debug=True)