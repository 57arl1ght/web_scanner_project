import requests
import urllib.parse

def scan_vulnerabilities(url):
    """Перевіряє GET-параметри URL на базові вразливості з класифікацією OWASP/CWE."""
    results = []
    
    if "?" not in url:
        return ["Параметри в URL не знайдені. Спробуйте URL формату http://site.com/page?id=1"]
        
    base_url, query_string = url.split("?", 1)
    params = urllib.parse.parse_qs(query_string)
    
    # Payloads
    sqli_payloads = ["'", "\"", "1' OR '1'='1", "1; DROP TABLE users"]
    sqli_errors = ["syntax error", "mysql", "sql syntax", "ora-", "postgresql"]
    
    xss_payload = "<script>alert('XSS')</script>"
    
    lfi_payloads = ["../../../../etc/passwd", "..\\..\\..\\windows\\win.ini"]
    lfi_errors = ["root:x:0:0", "[extensions]"]

    for param_name, param_values in params.items():
        original_value = param_values[0]
        
        # 1. SQL Injection (CWE-89)
        for payload in sqli_payloads:
            test_url = f"{base_url}?{param_name}={original_value}{payload}"
            try:
                res = requests.get(test_url, timeout=5)
                if any(error in res.text.lower() for error in sqli_errors):
                    # ДОДАНО КЛАСИФІКАЦІЮ OWASP ТА CWE
                    results.append(f"[🛑 Високий Ризик] SQL Injection у параметрі '{param_name}'\n    └─ Класифікація: CWE-89 | OWASP A03:2021-Injection")
                    break 
            except requests.RequestException:
                pass

        # 2. XSS (CWE-79)
        test_url_xss = f"{base_url}?{param_name}={urllib.parse.quote(xss_payload)}"
        try:
            res = requests.get(test_url_xss, timeout=5)
            if xss_payload in res.text:
                # ДОДАНО КЛАСИФІКАЦІЮ OWASP ТА CWE
                results.append(f"[⚠️ Середній Ризик] Reflected XSS у параметрі '{param_name}'\n    └─ Класифікація: CWE-79 | OWASP A03:2021-Injection")
        except requests.RequestException:
            pass
            
        # 3. Directory Traversal / LFI (CWE-22)
        for payload in lfi_payloads:
            test_url_lfi = f"{base_url}?{param_name}={payload}"
            try:
                res = requests.get(test_url_lfi, timeout=5)
                if any(error in res.text.lower() for error in lfi_errors):
                    # ДОДАНО КЛАСИФІКАЦІЮ OWASP ТА CWE
                    results.append(f"[🛑 Високий Ризик] Directory Traversal (LFI) у параметрі '{param_name}'\n    └─ Класифікація: CWE-22 | OWASP A01:2021-Broken Access Control")
                    break
            except requests.RequestException:
                pass

    if not results:
        results.append("Вразливостей не виявлено (або вони захищені WAF).")
        
    return results