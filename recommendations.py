# recommendations.py

import logging

# Module-specific logger
logger = logging.getLogger(__name__)

def generate_recommendations(details):
    """
    Generate actionable recommendations based on the OSINT findings.
    
    Args:
        details (dict): The OSINT analysis results.

    Returns:
        list: A list of actionable recommendations.
    """
    logger.info("Generating recommendations based on findings...")

    recommendations = []

    # Email validation
    if "Validation" in details:
        if "valid" not in details["Validation"].lower():
            recommendations.append("Check the email format and ensure the domain exists.")
        else:
            recommendations.append("Email is valid. Proceed with further analysis.")

    # WHOIS information
    if "WHOIS" in details:
        whois = details["WHOIS"]
        if isinstance(whois, dict):
            if "Expiration Date" in whois:
                recommendations.append("Check domain expiration date to ensure it's still active.")
            if "Organization" in whois:
                recommendations.append("Verify the organization's authenticity to avoid scams.")

    # Reverse DNS
    if "Reverse DNS" in details:
        reverse_dns = details["Reverse DNS"]
        if isinstance(reverse_dns, dict) and "Error" in reverse_dns:
            recommendations.append("Reverse DNS lookup failed. Check the domain's DNS configuration.")
        else:
            recommendations.append("Reverse DNS records appear valid.")

    # Mail server details
    if "Mail Server Details" in details:
        mail_details = details["Mail Server Details"]
        if isinstance(mail_details, dict):
            if "No SPF record found." in mail_details.get("SPF", ""):
                recommendations.append("Add an SPF record to prevent email spoofing.")
            if "No DMARC record found." in mail_details.get("DMARC", ""):
                recommendations.append("Add a DMARC record to enforce email authentication.")

    # VirusTotal reputation
    if "VirusTotal Reputation" in details:
        vt_reputation = details["VirusTotal Reputation"]
        if isinstance(vt_reputation, dict):
            if vt_reputation.get("Analysis Stats", {}).get("malicious", 0) > 0:
                recommendations.append("The domain has been flagged as malicious. Avoid interacting with it.")
            else:
                recommendations.append("The domain appears clean according to VirusTotal.")

    # Have I Been Pwned results
    if "HIBP Results" in details:
        hibp_results = details["HIBP Results"]
        if isinstance(hibp_results, list) and hibp_results:
            recommendations.append("The email has been found in data breaches. Update passwords immediately.")
        elif isinstance(hibp_results, str) and "No breaches found" in hibp_results:
            recommendations.append("No breaches found. Continue monitoring for potential leaks.")

    # Social media accounts
    if "Social Media Accounts" in details:
        social_media = details["Social Media Accounts"]
        found_accounts = social_media.get("Found Accounts", {})
        if found_accounts:
            recommendations.append("Verify the legitimacy of the associated social media accounts.")
        else:
            recommendations.append("No social media accounts found. Consider verifying manually.")

    # General recommendation if no actionable findings
    if not recommendations:
        recommendations.append("No significant findings. Proceed with caution and monitor the domain regularly.")

    logger.info(f"Generated {len(recommendations)} recommendations.")
    return recommendations
