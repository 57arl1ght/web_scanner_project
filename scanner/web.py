import requests
import re
from bs4 import BeautifulSoup

def check_security_headers(url):
    """Перевіряє наявність базових HTTP заголовків безпеки з прив'язкою до OWASP."""
    security_headers = [
        'Content-Security-Policy',
        'X-Frame-Options',
        'X-XSS-Protection',
        'Strict-Transport-Security'
    ]
    results = {}
    
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        
        for header in security_headers:
            if header in headers:
                results[header] = "Знайдено (Добре)"
            else:
                results[header] = "Відсутній (Ризик: CWE-693 | OWASP A05:2021-Security Misconfiguration)"
    except requests.RequestException:
        return {"Помилка": "Неможливо отримати заголовки"}
        
    return results

def detect_technologies(url):
    """Визначає технології та їх точні версії за заголовками та HTML-кодом."""
    detected = []
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        html_content = response.text
        html_lower = html_content.lower()
        
        # 1. Точне визначення вебсервера (наприклад: nginx/1.18.0 або Apache/2.4.41)
        server_header = headers.get('Server', '')
        if server_header:
            # Беремо перше слово до пробілу, щоб відкинути зайве сміття типу "(Ubuntu)"
            main_server_info = server_header.split(' ')[0]
            detected.append(f"Сервер: {main_server_info}")
        
        # 2. Точне визначення движка/мови (наприклад: PHP/8.1.2)
        powered_by = headers.get('X-Powered-By', '')
        if powered_by:
            detected.append(f"Движок: {powered_by}")
            
        # 3. Визначення точної версії CMS (наприклад, WordPress) через мета-теги
        # Шукаємо щось на зразок: <meta name="generator" content="WordPress 6.1.1" />
        wp_version = re.search(r'<meta name="generator"\s+content="(WordPress.*?)"', html_content, re.IGNORECASE)
        if wp_version:
            detected.append(wp_version.group(1)) # Додасть "WordPress 6.1.1"
        elif 'wp-content' in html_lower:
            detected.append('WordPress (версія прихована адміністратором)')

        # 4. Визначення популярних фронтенд фреймворків
        if 'react' in html_lower or 'data-reactroot' in html_lower:
            detected.append('React.js')
        if 'vue' in html_lower or 'data-v-' in html_lower:
            detected.append('Vue.js')
            
    except requests.RequestException:
        pass
        
    return list(set(detected)) if detected else ["Технології не визначено"]