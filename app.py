from flask import Flask, render_template, request
import re
import ipaddress
from urllib.parse import urlsplit, parse_qs

app = Flask(__name__)


# --------------------------------------------------
# URL VALIDATION
# --------------------------------------------------

def is_valid_url(url):

    if not url or len(url) > 2048:
        return False

    if any(character.isspace() for character in url):
        return False

    try:
        parsed_url = urlsplit(url)

        if parsed_url.scheme.lower() not in ["http", "https"]:
            return False

        hostname = parsed_url.hostname

        if not hostname:
            return False

        # Check whether the hostname is a valid IP address.
        try:
            ipaddress.ip_address(hostname)
            return True

        except ValueError:
            pass

        # Validate a regular domain name.
        hostname = hostname.rstrip(".").encode("idna").decode("ascii")

        if len(hostname) > 253:
            return False

        labels = hostname.split(".")

        for label in labels:

            if not re.fullmatch(
                r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?",
                label
            ):
                return False

        return True

    except (ValueError, UnicodeError):
        return False


# --------------------------------------------------
# URL SECURITY ANALYSIS
# --------------------------------------------------

def analyze_url(url):

    risk_score = 0
    reasons = []

    url_lower = url.lower()

    parsed_url = urlsplit(url_lower)

    domain = parsed_url.hostname or ""
    path = parsed_url.path
    query = parsed_url.query

    # --------------------------------------------------
    # Check 1: HTTPS
    # --------------------------------------------------

    if parsed_url.scheme != "https":

        risk_score += 20

        reasons.append(
            "Website does not use HTTPS"
        )

    # --------------------------------------------------
    # Check 2: IP address instead of domain
    # --------------------------------------------------

    is_ip_address = False

    try:
        ipaddress.ip_address(domain)
        is_ip_address = True

    except ValueError:
        pass

    if is_ip_address:

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
    # Check 5: Suspicious keywords in URL path
    # --------------------------------------------------

    suspicious_words = [
        "login",
        "verify",
        "account",
        "free",
        "claim"
    ]

    found_words = []

    for word in suspicious_words:

        if word in path:

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
    # Check 7: Look-alike domain detection
    # --------------------------------------------------

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

    if not is_ip_address:

        domain_parts = domain.split(".")

        if len(domain_parts) > 3:

            risk_score += 15

            reasons.append(
                "URL contains an unusually large number "
                "of subdomains"
            )

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

    if any(
        domain == shortener or domain.endswith("." + shortener)
        for shortener in shorteners
    ):

        risk_score += 15

        reasons.append(
            "URL uses a URL shortening service"
        )

    # --------------------------------------------------
    # Check 10: Suspicious characters
    # --------------------------------------------------

    if "\\" in url:

        risk_score += 10

        reasons.append(
            "URL contains unusual characters or patterns"
        )

    # --------------------------------------------------
    # Check 11: Non-standard port
    # --------------------------------------------------

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

    suspicious_parameters = [
        "password",
        "passwd",
        "token",
        "auth",
        "verify",
        "redirect"
    ]

    found_parameters = []

    query_parameters = parse_qs(
        query,
        keep_blank_values=True
    )

    for parameter in suspicious_parameters:

        if parameter in query_parameters:

            found_parameters.append(parameter)

    if found_parameters:

        risk_score += 15

        reasons.append(
            "Suspicious query parameters found: "
            + ", ".join(found_parameters)
        )

    # --------------------------------------------------
    # Check 13: Excessive query length
    # --------------------------------------------------

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
# HOME PAGE
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

            try:

                risk_score, risk_level, reasons = analyze_url(url)

                result = {
                    "url": url,
                    "score": risk_score,
                    "level": risk_level,
                    "reasons": reasons
                }

            except ValueError:

                result = {
                    "url": url,
                    "score": 0,
                    "level": "Invalid URL",
                    "reasons": [
                        "The URL contains an invalid format or port."
                    ]
                }

    return render_template(
        "index.html",
        result=result
    )


# --------------------------------------------------
# RUN FLASK APPLICATION
# --------------------------------------------------

if __name__ == "__main__":

    app.run(debug=True)