# Next_Sight_AI_Powered_Email_OSINT.py, contact us for premium OSINT services at info@next-sight.com

import os
import logging
import sys
from prettytable import PrettyTable
from config import ascii_header
from validators import validate_email
from whois_utils import domain_whois
from dns_utils import reverse_dns_lookup, get_mail_server_details, geolocate_ip
from reputation import domain_reputation, hibp_check, calculate_risk_score
from social_media import social_media_lookup
from summarize_with_chunks import summarize_with_chunks
from report_utils import save_results_to_excel
from report_generation import generate_detailed_report
from recommendations import generate_recommendations
from pathlib import Path

# Configure logging to use UTF-8 encoding and ensure cross-platform compatibility
log_file = Path("osint_log.txt")  # Define log file path using pathlib
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s]: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),  # Console output
        logging.FileHandler(str(log_file), mode="w", encoding="utf-8")  # Log file output
    ]
)
logger = logging.getLogger("Next_Sight_AI_OSINT")


def display_summary(details):
    """Display a neatly formatted summary of the analysis."""
    table = PrettyTable()
    table.field_names = ["Category", "Details"]

    for key, value in details.items():
        if key in ["AI Summary", "Risk Score", "Recommendations"]:
            continue
        if isinstance(value, dict):
            for subkey, subvalue in value.items():
                table.add_row([f"{key} - {subkey}", str(subvalue)])
        else:
            table.add_row([key, str(value)])

    print("\n📊 Analysis Summary:\n")
    print(table)
    logger.info("Analysis summary displayed to user.")


def main():
    print("\n🔍 Welcome to Next Sight AI-Powered Email OSINT Tool!")
    logger.info("Welcome message displayed.")
    print(ascii_header)

    try:
        while True:
            email = input("📧 Please enter a valid email address (or type 'exit' to quit): ").strip()

            if email.lower() == 'exit':
                print("🚪 Exiting the tool. Goodbye!")
                logger.info("User exited the tool.")
                break

            print("\n⏳ Validating email address...")
            logger.info(f"Validating email: {email}")
            is_valid, validation_message = validate_email(email)

            if not is_valid:
                print(f"❌ Invalid email: {validation_message}. Please try again.")
                logger.error(f"Email validation failed: {validation_message}")
                continue

            print(f"✅ Email validated: {email}. Proceeding with analysis...")
            logger.info(f"Email validated successfully: {email}")

            domain = email.split('@')[1]
            details = {
                "Validation": validation_message,
                "WHOIS": domain_whois(email),
                "Reverse DNS": reverse_dns_lookup(domain),
                "Mail Server Details": get_mail_server_details(domain),
            }

            # VirusTotal Reputation Check
            vt_api_key = os.getenv("VT_API_KEY", input("Enter VirusTotal API Key (or press Enter to skip): ").strip())
            if vt_api_key:
                try:
                    details["VirusTotal Reputation"] = domain_reputation(domain, vt_api_key)
                except Exception as e:
                    logger.error(f"VirusTotal error: {e}")
                    details["VirusTotal Reputation"] = {"Error": "VirusTotal check failed."}
            else:
                details["VirusTotal Reputation"] = {"Warning": "No API key provided."}

            # Have I Been Pwned Check
            hibp_results = hibp_check(email)
            if hibp_results == "API key missing":
                details["HIBP Results"] = {"Warning": "No API key provided."}
            else:
                details["HIBP Results"] = hibp_results

            # Social Media Lookup
            details["Social Media Accounts"] = social_media_lookup(email)

            # Risk Score Calculation
            try:
                details["Risk Score"] = calculate_risk_score(
                    details.get("VirusTotal Reputation", {}),
                    details.get("HIBP Results", [])
                )
            except Exception as e:
                details["Risk Score"] = {"Error": "Risk score calculation failed."}
                logger.error(f"Risk score calculation failed: {e}")

            # Geolocation Integration
            print("🌍 Performing geolocation for resolved IPs...")
            resolved_ips = details.get("Reverse DNS", {}).get("IPs", [])
            if not resolved_ips:
                details["Geolocation"] = "No IPs resolved for geolocation."
                print("⚠️ No resolved IPs available for geolocation.")
                logger.warning("No resolved IPs available for geolocation.")
            else:
                try:
                    geolocation_results = geolocate_ip(resolved_ips)
                    details["Geolocation"] = geolocation_results
                    print("✅ Geolocation completed.")
                    logger.info("Geolocation completed successfully.")
                except Exception as e:
                    details["Geolocation"] = {"Error": str(e)}
                    print("❌ Geolocation failed. Please check the logs.")
                    logger.error(f"Geolocation failed: {e}")

            # AI Summary
            try:
                report_text = "\n".join([f"{key}: {value}" for key, value in details.items()])
                details["AI Summary"] = summarize_with_chunks(report_text)
            except Exception as e:
                details["AI Summary"] = "Failed to generate AI summary."
                logger.error(f"AI summary error: {e}")

            # Recommendations
            try:
                details["Recommendations"] = generate_recommendations(details)
            except Exception as e:
                details["Recommendations"] = "Failed to generate recommendations."
                logger.error(f"Recommendations generation error: {e}")

            # Detailed Report
            detailed_report = generate_detailed_report(details, details.get("AI Summary", ""))
            try:
                filename = save_results_to_excel(email, details, details.get("AI Summary", ""), detailed_report)
                print(f"✅ Results saved to {filename}")
            except Exception as e:
                logger.error(f"Excel save error: {e}")

            break

    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)


if __name__ == "__main__":
    main()
