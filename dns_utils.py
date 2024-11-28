import dns.resolver
import socket
import logging
import requests

logger = logging.getLogger(__name__)

# DNS and Geolocation Utilities

def resolve_dns(domain, record_type):
    """Resolve specific DNS records for a domain."""
    try:
        answers = dns.resolver.resolve(domain, record_type)
        return [answer.to_text() for answer in answers]
    except Exception as e:
        return [f"Error resolving {record_type}: {e}"]

def reverse_dns_lookup(ip_address):
    """Perform reverse DNS lookup for an IP address."""
    try:
        reverse_dns = socket.gethostbyaddr(ip_address)
        logger.info(f"Reverse DNS lookup successful for {ip_address}.")
        return {
            "Hostname": reverse_dns[0],
            "Aliases": reverse_dns[1],
            "IPs": reverse_dns[2]
        }
    except Exception as e:
        logger.error(f"Reverse DNS lookup failed for {ip_address}: {e}")
        return {"Error": f"Reverse DNS lookup failed: {e}"}

def geolocate_ip(ip_list):
    """
    Geolocate a list of IP addresses using IP-API.
    Args:
        ip_list (list): List of IP addresses to geolocate.

    Returns:
        dict: Geolocation data for each IP.
    """
    logger.info("Starting geolocation of IP addresses...")
    results = {}
    for ip in ip_list:
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}")
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    results[ip] = {
                        "Country": data.get("country"),
                        "Region": data.get("regionName"),
                        "City": data.get("city"),
                        "Latitude": data.get("lat"),
                        "Longitude": data.get("lon"),
                        "ISP": data.get("isp"),
                    }
                    logger.info(f"Geolocation successful for IP: {ip}")
                else:
                    results[ip] = {"Error": data.get("message", "Unknown error")}
                    logger.warning(f"Geolocation failed for IP {ip}: {data.get('message')}")
            else:
                results[ip] = {"Error": f"HTTP {response.status_code}"}
                logger.error(f"HTTP error during geolocation for IP {ip}: {response.status_code}")
        except Exception as e:
            results[ip] = {"Error": str(e)}
            logger.error(f"Error geolocating IP {ip}: {str(e)}")
    return results

def get_mail_server_details(domain):
    """Fetch MX, SPF, DKIM, DMARC records."""
    logger.info(f"Fetching mail server details for domain: {domain}")
    
    # MX Records
    mx_records = resolve_dns(domain, 'MX')
    
    # TXT Records (to extract SPF, DKIM, and DMARC)
    txt_records = resolve_dns(domain, 'TXT')
    spf = [record for record in txt_records if 'v=spf1' in record]
    dmarc = [record for record in txt_records if '_dmarc' in record]
    dkim = [record for record in txt_records if 'v=DKIM1' in record]

    results = {
        "MX Records": mx_records or "No MX records found.",
        "SPF": spf or "No SPF record found.",
        "DMARC": dmarc or "No DMARC record found.",
        "DKIM": dkim or "No DKIM record found."
    }
    logger.info(f"Mail server details fetched successfully for {domain}.")
    return results
