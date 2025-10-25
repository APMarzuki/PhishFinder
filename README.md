🚨 PhishFinder: Automated Phishing Email Analyzer (Web GUI)
PhishFinder is a Python utility designed for Cybersecurity Analysts and Incident Responders to quickly parse and analyze suspicious email messages. It automatically extracts key indicators of compromise (IOCs) for triage and reporting.

It helps to rapidly determine the true origin of an email by analyzing its headers, enriching IP data, and identifying malicious URLs in the body content.

The application has been upgraded to a Streamlit Web GUI for easy, copy-and-paste, file-free analysis.

🎯 Key Features
Web GUI Interface: Run the application locally and access it in your browser for intuitive, real-time analysis.

Header Analysis: Extracts critical fields like Subject, From, Return-Path (to detect spoofing), and the Connecting IP address.

Threat Enrichment: Uses RDAP/WHOIS lookups to identify the Originating Network (ASN/Organization) and Country of the connecting IP.

URL Extraction: Scans the email body (plain text and HTML parts) for potentially malicious links.

Actionable Report: Generates a structured report directly in the web browser, highlighting key mismatches and recommended next steps (e.g., sandboxing URLs).
Installation and Setup
This project requires Python 3.x and the use of a Virtual Environment (venv) is strongly recommended.

1. Clone the Repository
Bash 
git clone [YOUR_GITHUB_REPO_URL]
cd PhishFinder
2. Create and Activate Virtual Environment
python -m venv .venv
# Windows
.\.venv\Scripts\activate
# macOS/Linux
source .venv/bin/activate
3. Install Dependencies
The project now requires the streamlit library in addition to core dependencies.
pip install -r requirements.txt
4. 🚀 Usage (Running the Web Application)
The analysis is performed via the web application using the app.py entry point.
Ensure your virtual environment is active: (.venv) should be visible in your terminal.
Run the Streamlit application:
streamlit run app.py
5. Access the App: Your browser will automatically open to http://localhost:8501.
Analysis Steps
Obtain Raw Email Source: Open the suspicious email in your client (e.g., Gmail, Outlook) and select the option to "View Original" or "Show Message Source."
Copy All Content: Copy the entire text block, ensuring you include all headers (starting with Received:).
Paste & Analyze: Paste the complete raw content into the large text area on the web page and click "Analyze Email Source."
6. 💻 Core Functions
The entire analysis workflow is performed by the PhishFinder class in phishfinder/analyzer.py.
7. Function Name,Purpose
"__init__(self, email_raw_content)",Parses the raw string input into a structured EmailMessage object.
analyze_and_report(self),Orchestrates the entire analysis workflow and generates the final structured report.
_extract_headers(self),"Determines the true sender path, extracting From, Return-Path, and the Connecting_IP."
_extract_urls(self),Uses regex to scan all email parts (HTML/text) and extract unique URLs for sandboxing.
_enrich_data(self),Performs a WHOIS/RDAP lookup on the Connecting_IP to determine the Originating Network (ASN) and IP Country.