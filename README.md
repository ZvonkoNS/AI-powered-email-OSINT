
# AI-Powered Email OSINT Tool

Welcome to the **AI-Powered Email OSINT Tool** — an advanced open-source intelligence (OSINT) framework designed to analyze email addresses and their associated domains with AI-enhanced analysis. This tool combines several OSINT techniques, integrations, and AI-driven summaries to deliver actionable insights and recommendations.

---

## 🔥 Features

1. **Email Validation**:
   - Validates email syntax.
   - Confirms if the domain is active and reachable.

2. **WHOIS Lookup**:
   - Fetches registration details such as:
     - Registrar information.
     - Creation, expiration, and update dates.
     - Registrant organization.

3. **Reverse DNS Lookup**:
   - Performs reverse lookups for associated IPs.
   - Retrieves hostnames, aliases, and related IPs.

4. **Mail Server Details**:
   - Queries DNS for `MX`, `SPF`, `DKIM`, and `DMARC` records.
   - Provides mail server configuration and anti-spoofing details.

5. **VirusTotal Reputation Check**:
   - Queries the VirusTotal API for:
     - Domain reputation scores.
     - Last analysis statistics and categories.

6. **Have I Been Pwned (HIBP) Integration**:
   - Identifies if the email appears in known data breaches (requires an API key).

7. **Social Media Lookup**:
   - Attempts to identify associated social media accounts.

8. **AI-Driven Summarization**:
   - Provides concise AI-generated summaries of findings.

9. **Geolocation**:
   - Resolves geolocation data for domain-related IP addresses.

10. **Risk Score**:
    - Generates a risk score based on:
      - VirusTotal reputation.
      - HIBP breach data.
      - Security configurations (SPF, DKIM, DMARC).

11. **Recommendations**:
    - Offers actionable AI-driven recommendations to enhance security.

12. **Export to Excel**:
    - Saves all results and recommendations in an Excel file for offline use.

---

## 🛠️ Setup Instructions

### 1. Clone the Repository
```bash
git clone https://github.com/ZvonkoNS/AI-powered-email-OSINT.git
cd AI-powered-email-OSINT
```

### 2. Install Dependencies
Install the required Python packages:
```bash
pip install -r requirements.txt
```
Dependencies include:
- `prettytable`: For CLI table formatting.
- `openpyxl`: For Excel generation.
- `transformers`: For AI summarization.
- `requests`: For API interactions.
- `dnspython`: For DNS lookups.

### 3. Environment Setup
Set up environment variables for API keys:
```bash
export VT_API_KEY="your_virustotal_api_key"
export HIBP_API_KEY="your_hibp_api_key"
```

### 4. Run the Tool
Execute the main script:
```bash
python Next_Sight_AI_Powered_Email_OSINT.py
```

---

## 🧰 How to Use

1. **Input an Email**:
   - When prompted, enter the email address to analyze.

2. **Perform Analysis**:
   - The tool validates, performs WHOIS, DNS lookups, and more.

3. **API Key Prompts**:
   - If API keys are missing, the tool prompts for manual input.

4. **View Results**:
   - Summarized results are displayed in the terminal and saved to an Excel file.

5. **Check Recommendations**:
   - Security recommendations are provided for actionable insights.

---

## 📂 Project Structure

```plaintext
AI-powered-email-OSINT/
├── config.py                   # ASCII header configuration
├── dns_utils.py                # DNS and geolocation functions
├── Next_Sight_AI_Powered_Email_OSINT.py  # Main script
├── recommendations.py          # Security recommendations
├── report_generation.py        # AI-driven report generation
├── report_utils.py             # Excel export handling
├── reputation.py               # VirusTotal and HIBP functions
├── social_media.py             # Social media lookup utilities
├── summarize_with_chunks.py    # AI text summarization
├── validators.py               # Email validation logic
├── whois_utils.py              # WHOIS lookup utilities
├── requirements.txt            # Dependency list
├── LICENSE.txt                 # License details
└── README.md                   # Documentation
```

---

## 🔑 License
This project is licensed under the MIT License. See the LICENSE.txt file for more details.

---

## 🤝 Contributions
Contributions are welcome! Fork the project and submit pull requests. Ensure code adheres to best practices with tests and documentation.

---

## 📧 Contact
For queries, feature requests, or premium OSINT services, contact:
- Email: info@next-sight.com or zvonko@next-sight.com
- Website: [Next Sight](https://next-sight.com)
