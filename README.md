# 🚨 PhishFinder: Automated Phishing Email Analyzer

PhishFinder is a Python utility designed for Cybersecurity Analysts and Incident Responders to quickly parse and analyze suspicious email files (EML format) and extract key indicators of compromise (IOCs) for triage and reporting.

It helps to rapidly determine the *true* origin of an email by analyzing its headers, enriching IP data, and identifying malicious URLs in the body content.

***

## 🎯 Key Features

* **Header Analysis:** Extracts critical fields like **Subject**, **From**, **Return-Path** (to detect spoofing), and the **Connecting IP** address.
* **Threat Enrichment:** Uses RDAP/WHOIS lookups to identify the **Originating Network** (ASN/Organization) and **Country** of the connecting IP.
* **URL Extraction:** Scans the email body (plain text and HTML parts) for potentially malicious links.
* **Actionable Report:** Generates a structured, console-based report highlighting key mismatches and recommended next steps (e.g., sandboxing URLs).

***

## 🛠️ Installation and Setup

This project requires Python 3.x and the use of a Virtual Environment (`venv`) is strongly recommended.

### 1. Clone the Repository

```bash
git clone [YOUR_GITHUB_REPO_URL]
cd PhishFinder