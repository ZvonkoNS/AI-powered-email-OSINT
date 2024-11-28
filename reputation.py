import os
import requests
import logging

logger = logging.getLogger(__name__)

# Safe JSON parser utility
def safe_json(response):
    """Parse JSON safely from a response object."""
    try:
        return response.json()
    except requests.JSONDecodeError:
        return None

# VirusTotal Reputation Check
def domain_reputation(domain, api_key=None):
    """Check domain reputation using VirusTotal API."""
    logger.info(f"Checking VirusTotal reputation for domain: {domain}")

    if not api_key:
        logger.warning("VirusTotal API Key not provided. Skipping reputation check.")
        return "Skipped: No API key provided."

    api_url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(api_url, headers=headers)
        if response.status_code == 200:
            data = safe_json(response)
            if data:
                categories = data.get("data", {}).get("attributes", {}).get("categories", {})
                analysis_stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                logger.info("VirusTotal reputation check successful.")
                return {"Categories": categories, "Analysis Stats": analysis_stats}
            else:
                logger.warning("VirusTotal returned no data.")
                return "No reputation data found."
        elif response.status_code == 403:
            logger.error("Invalid API key or access denied by VirusTotal.")
            return "Error: Invalid API key or access denied."
        elif response.status_code == 404:
            logger.info("Domain not found in VirusTotal database.")
            return "No data available for the domain."
        else:
            logger.error(f"VirusTotal error {response.status_code}: {response.text}")
            return f"Error: {response.status_code} - {response.text}"
    except Exception as e:
        logger.error(f"Error querying VirusTotal API: {str(e)}")
        return {"Error": str(e)}


# Have I Been Pwned Check
def hibp_check(email):
    """Check if the email is in data breaches using Have I Been Pwned API."""
    logger.info(f"Checking Have I Been Pwned breaches for email: {email}")

    hibp_api_key = os.getenv("HIBP_API_KEY")
    if not hibp_api_key:
        logger.warning("HIBP API Key not provided. Prompting user...")
        hibp_api_key = input("Enter your HIBP API Key (or press Enter to skip): ").strip()

    if not hibp_api_key:
        logger.warning("HIBP API Key not provided. Skipping breach check.")
        return "HIBP check skipped due to missing API key."

    api_url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    headers = {
        "hibp-api-key": hibp_api_key,
        "User-Agent": "NextSight-AI-OSINT"
    }

    try:
        response = requests.get(api_url, headers=headers)
        if response.status_code == 200:
            breaches = response.json()
            if breaches:
                logger.info(f"Found {len(breaches)} breaches for email: {email}")
                return [breach['Name'] for breach in breaches]
            else:
                logger.info(f"No breaches found for email: {email}")
                return "No breaches found."
        elif response.status_code == 401:
            logger.error("Invalid HIBP API key. Please verify your subscription.")
            return "Error: Invalid HIBP API key. Ensure it is valid and active."
        elif response.status_code == 404:
            logger.info(f"No breaches found for email: {email}")
            return "No breaches found."
        else:
            logger.error(f"HIBP error {response.status_code}: {response.text}")
            return f"Error: {response.status_code} - {response.text}"
    except Exception as e:
        logger.error(f"Error querying HIBP API: {str(e)}")
        return {"Error": str(e)}

# Calculate Risk Score
def calculate_risk_score(domain_reputation_result, hibp_results):
    logger.info("Calculating risk score...")
    try:
        # Handle missing or empty inputs
        if not domain_reputation_result or not isinstance(domain_reputation_result, dict):
            logger.warning("Invalid or missing domain reputation data.")
            return {"Risk Level": "Unknown", "Reason": "Missing domain reputation data."}

        if not hibp_results or hibp_results == "No breaches found.":
            hibp_score = 0
        elif isinstance(hibp_results, list):
            hibp_score = len(hibp_results)  # Number of breaches
        else:
            hibp_score = 10  # Default high score for unrecognized input

        vt_malicious = domain_reputation_result.get("Analysis Stats", {}).get("malicious", 0)
        risk_score = vt_malicious + hibp_score

        # Assign a risk level based on score
        if risk_score == 0:
            risk_level = "Low"
        elif risk_score < 5:
            risk_level = "Medium"
        else:
            risk_level = "High"

        return {"Risk Level": risk_level, "Details": f"Malicious: {vt_malicious}, Breaches: {hibp_score}"}
    except Exception as e:
        logger.error(f"Error calculating risk score: {e}")
        return {"Risk Level": "Error", "Reason": str(e)}


    # Analyze VirusTotal reputation
    if isinstance(domain_reputation, dict):
        positives = domain_reputation.get("Analysis Stats", {}).get("malicious", 0)
        score += positives * 2  # Malicious detections increase risk
        breakdown["VirusTotal"] = f"Malicious detections: {positives}"
    else:
        breakdown["VirusTotal"] = "No data or skipped."

    # Analyze HIBP results
    if isinstance(hibp_results, list):
        breaches_count = len(hibp_results)
        score += breaches_count * 1  # Each breach increases risk
        breakdown["HIBP"] = f"Breaches found: {breaches_count}"
    elif isinstance(hibp_results, str) and hibp_results.startswith("No breaches"):
        breakdown["HIBP"] = "No breaches found."
    else:
        breakdown["HIBP"] = "No data or skipped."

    # Normalize score
    risk_level = "Low"
    if score > 5:
        risk_level = "High"
    elif score > 2:
        risk_level = "Moderate"

    logger.info(f"Risk score calculation completed. Risk Level: {risk_level}")
    return {"Risk Score": score, "Risk Level": risk_level, "Breakdown": breakdown}
