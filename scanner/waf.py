import requests

def detect_waf(url):
    """
    Визначає наявність Web Application Firewall (WAF).
    Відправляє шкідливий payload і аналізує заголовки/тіло відповіді на предмет блокування.
    """
    waf_signatures = {
        "Cloudflare": ["cloudflare", "__cfduid", "cf-ray"],
        "AWS WAF": ["x-amzn-requestid", "x-amzn-trace-id"],
        "Akamai": ["x-akamai-request-id", "akamai"],
        "Sucuri": ["x-sucuri-id", "x-sucuri-cache"],
        "Imperva / Incapsula": ["incapsula", "x-iinfo"],
        "F5 BIG-IP": ["big-ip", "f5"],
    }
    
    
    malicious_payload = "?id=1 AND 1=1 UNION SELECT 1,2,3--&test=<script>alert('WAF_TEST')</script>"
    test_url = url + malicious_payload if "?" not in url else url + "&" + malicious_payload.lstrip("?")
    
    try:
       
        response = requests.get(test_url, timeout=5, allow_redirects=True)
        headers_str = str(response.headers).lower()
        
        detected_waf = None
        
        
        for waf_name, signatures in waf_signatures.items():
            if any(sig in headers_str for sig in signatures):
                detected_waf = waf_name
                break
                
        
        if not detected_waf and response.status_code in [403, 406]:
            if "mod_security" in response.text.lower() or "modsecurity" in headers_str:
                detected_waf = "ModSecurity"
            else:
                detected_waf = "Невідомий WAF (Generic Firewall)"
                
        if detected_waf:
            return f"🛡️ Виявлено захист: {detected_waf} (Можливе блокування сканування)"
        else:
            return "WAF не виявлено (Сайт безпосередньо відкритий для сканування)"
            
    except requests.RequestException:
        return "Не вдалося перевірити WAF (Таймаут або помилка з'єднання)"
