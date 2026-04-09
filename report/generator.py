import datetime

def generate_txt_report(data):
    """Створює текстовий звіт за результатами сканування."""
    filename = f"scan_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    
    with open(filename, "w", encoding="utf-8") as f:
        f.write("="*50 + "\n")
        f.write(" ЗВІТ ПРО СТАН БЕЗПЕКИ ВЕБРЕСУРСУ \n")
        f.write("="*50 + "\n\n")
        
        f.write(f"Дата сканування: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Цільовий URL: {data['url']}\n\n")
        
        f.write("[1] ВІДКРИТІ ПОРТИ:\n")
        if data['ports']:
            for port in data['ports']:
                f.write(f" - Порт {port}: Відкрито\n")
        else:
            f.write(" - Відкритих портів не знайдено (або заблоковано фаєрволом)\n")
            
        f.write("\n[2] SSL СЕРТИФІКАТ:\n")
        f.write(f" - {data['ssl']}\n")

        f.write("\n[3] ЗНАЙДЕНІ СУБДОМЕНИ:\n")
        if data.get('subdomains'):
            for subdomain in data['subdomains']:
                f.write(f" - {subdomain}\n")
        else:
            f.write(" - Субдомени не знайдено.\n")

        f.write("\n[4] ТЕХНОЛОГІЇ:\n")
        for tech in data['tech']:
            f.write(f" - {tech}\n")

        f.write("\n[5] HTTP ЗАГОЛОВКИ БЕЗПЕКИ:\n")
        for header, status in data['headers'].items():
            f.write(f" - {header}: {status}\n")

        f.write("\n[6] ВИЯВЛЕНІ ВРАЗЛИВОСТІ В ПАРАМЕТРАХ:\n")
        for vuln in data['vulns']:
            f.write(f" - {vuln}\n")

        f.write("\n[7] ПРИХОВАНІ ДИРЕКТОРІЇ ТА ФАЙЛИ (Brute-force):\n")
        for directory in data.get('directories', []):
            f.write(f" - {directory}\n")
            
        f.write("\n" + "="*50 + "\n")
        f.write(" РЕКОМЕНДАЦІЇ:\n")
        f.write(" 1. Закрийте всі невикористовувані порти.\n")
        f.write(" 2. Налаштуйте відсутні HTTP заголовки безпеки (CSP, HSTS).\n")
        f.write(" 3. Використовуйте параметризовані запити для захисту від SQLi.\n")
        f.write(" 4. Обмежте доступ до адміністративних панелей (змініть стандартні URL).\n")
        f.write(" 5. Видаліть з публічного доступу файли конфігурацій (.env) та бекапи.\n")
        f.write("="*50 + "\n")
        
    return filename
