# 🛡️ Web Vulnerability Scanner & OSINT Tool

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Completed-success)

A comprehensive tool for automated Dynamic Application Security Testing (DAST) and Open-Source Intelligence (OSINT) gathering. This project was developed as part of a university diploma thesis in Cybersecurity.

## ✨ Key Features

The application features a user-friendly Graphical User Interface (GUI) allowing modular execution of the following security checks:

* **Reconnaissance & Network:** Open port scanning, SSL/TLS certificate validation, and exact version detection of web servers and frameworks.
* **WAF Detection:** Automatic identification of Web Application Firewalls (Cloudflare, AWS WAF, Akamai, Sucuri, etc.).
* **Attack Surface Mapping:** Built-in Web Crawler for automated discovery and mapping of internal website pages.
* **Vulnerability Scanning (DAST):** Active detection of SQL Injection (SQLi) and Cross-Site Scripting (XSS), mapped to OWASP Top 10 and CWE classifications.
* **Brute-Force:** Discovery of hidden directories and administrative panels.
* **OSINT Modules:** Extraction of unique email addresses (Information Disclosure) and discovery of hidden subdomains.
* **Reporting:** Generation of detailed, actionable HTML reports including remediation recommendations for identified threats.

## 🚀 Installation & Usage

1. Clone the repository:
```bash
git clone git clone [https://github.com/YOUR_USERNAME/YOUR_REPOSITORY_NAME.git]

pip install requests beautifulsoup4

python gui.py or main.py
