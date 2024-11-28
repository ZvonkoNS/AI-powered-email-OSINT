import whois

def domain_whois(email):
    domain = email.split('@')[1]
    try:
        domain_info = whois.whois(domain)
        return {
            "Registrar": domain_info.registrar,
            "Creation Date": domain_info.creation_date,
            "Expiration Date": domain_info.expiration_date,
            "Organization": domain_info.org
        }
    except Exception as e:
        return {"Error": f"WHOIS lookup failed: {e}"}