import datetime
import os
import urllib.parse

def generate_html_report(data):
    """Створює HTML-звіт із чітким розділенням 'Не знайдено' та 'Пропущено'."""
    
    parsed_url = urllib.parse.urlparse(data['url'])
    domain = parsed_url.netloc
    if not domain:
        domain = "unknown_site"
        
    domain = domain.replace(":", "_")
    date_str = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M')
    filename = f"Аудит_{domain}_{date_str}.html"
    
    # --- БАЗОВА ІНФОРМАЦІЯ ---
    if data.get('ports') is None:
        ports_str = "<em>Пропущено користувачем</em>"
    elif not data.get('ports'):
        ports_str = "Не знайдено відкритих портів"
    else:
        ports_str = ', '.join(map(str, data.get('ports')))

    if data.get('tech') is None:
        tech_str = "<em>Пропущено користувачем</em>"
    elif not data.get('tech'):
        tech_str = "Технології не визначено"
    else:
        tech_str = ', '.join(data.get('tech'))

    waf_status = data.get('waf', '<em>Пропущено користувачем</em>')
    ssl_status = data.get('ssl', '<em>Пропущено користувачем</em>')

    # --- КАРТА САЙТУ ---
    crawler_html = ""
    if data.get('crawler') is None:
        crawler_html = "<li style='color: gray;'><em>Пропущено користувачем.</em></li>"
    elif not data.get('crawler'):
        crawler_html = "<li>Внутрішніх сторінок не знайдено.</li>"
    else:
        for page in data.get('crawler'):
            crawler_html += f"<li><a href='{page}' target='_blank'>{page}</a></li>"

    # --- СУБДОМЕНИ ---
    subdomains_html = ""
    if data.get('subdomains') is None:
        subdomains_html = "<li style='color: gray;'><em>Пропущено користувачем.</em></li>"
    elif not data.get('subdomains'):
        subdomains_html = "<li>Субдомени не знайдено.</li>"
    else:
        for sub in data.get('subdomains'):
            subdomains_html += f"<li>{sub}</li>"
    
    # --- EMAIL ---
    emails_html = ""
    if data.get('emails') is None:
        emails_html = "<li style='color: gray;'><em>Пропущено користувачем.</em></li>"
    elif not data.get('emails'):
        emails_html = "<li>Email-адрес не виявлено.</li>"
    else:
        for email in data.get('emails'):
            emails_html += f"<li><a href='mailto:{email}'>{email}</a></li>"
    
    # --- ЗАГОЛОВКИ БЕЗПЕКИ ---
    headers_html = ""
    if data.get('headers') is None:
        headers_html = "<tr><td colspan='2' style='text-align: center; color: gray;'><em>Перевірку пропущено користувачем</em></td></tr>"
    elif not data.get('headers'):
        headers_html = "<tr><td colspan='2'>Заголовки відсутні.</td></tr>"
    else:
        for header, status in data.get('headers').items():
            row_class = "table-success" if "Добре" in status else "table-danger"
            headers_html += f"<tr class='{row_class}'><td>{header}</td><td>{status}</td></tr>"
        
    # --- ВРАЗЛИВОСТІ ---
    vulns_html = ""
    if data.get('vulns') is None:
        vulns_html = "<div class='alert' style='background-color: #f8f9fa; color: #6c757d; border: 1px solid #dee2e6;'><em>Сканування на вразливості пропущено користувачем.</em></div>"
    elif not data.get('vulns'):
        vulns_html = "<div class='alert alert-success'>Вразливостей не виявлено.</div>"
    else:
        for vuln in data.get('vulns'):
            if "Високий Ризик" in vuln:
                vulns_html += f"<div class='alert alert-danger'><strong>{vuln.replace('    └─', '<br>└─')}</strong></div>"
            elif "Середній Ризик" in vuln:
                vulns_html += f"<div class='alert alert-warning'><strong>{vuln.replace('    └─', '<br>└─')}</strong></div>"
            else:
                vulns_html += f"<div class='alert alert-info'>{vuln}</div>"

    # --- ДИРЕКТОРІЇ ---
    dirs_html = ""
    if data.get('directories') is None:
        dirs_html = "<li style='color: gray;'><em>Пропущено користувачем.</em></li>"
    elif not data.get('directories'):
        dirs_html = "<li>Прихованих директорій не знайдено.</li>"
    else:
        for directory in data.get('directories'):
            dirs_html += f"<li>{directory}</li>"

    html_content = f"""
    <!DOCTYPE html>
    <html lang="uk">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Звіт зі сканування: {domain}</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f8f9fa; color: #343a40; margin: 0; padding: 20px; }}
            .container {{ max-width: 900px; margin: 0 auto; background: #ffffff; padding: 30px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }}
            h1 {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
            h2 {{ color: #34495e; margin-top: 30px; font-size: 1.4em; border-left: 4px solid #3498db; padding-left: 10px; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 15px; margin-bottom: 15px; }}
            th, td {{ padding: 12px; border: 1px solid #dee2e6; text-align: left; }}
            th {{ background-color: #e9ecef; font-weight: bold; }}
            .table-success {{ background-color: #d4edda; }}
            .table-danger {{ background-color: #f8d7da; }}
            .alert {{ padding: 15px; margin-bottom: 15px; border: 1px solid transparent; border-radius: 4px; line-height: 1.5; }}
            .alert-danger {{ color: #721c24; background-color: #f8d7da; border-color: #f5c6cb; }}
            .alert-warning {{ color: #856404; background-color: #fff3cd; border-color: #ffeeba; }}
            .alert-success {{ color: #155724; background-color: #d4edda; border-color: #c3e6cb; }}
            .alert-info {{ color: #0c5460; background-color: #d1ecf1; border-color: #bee5eb; }}
            ul {{ line-height: 1.6; margin-left: 20px; }}
            .crawler-list {{ max-height: 300px; overflow-y: auto; background: #f1f3f5; padding: 15px; border-radius: 5px; border: 1px solid #dee2e6; }}
            .footer {{ margin-top: 40px; text-align: center; color: #6c757d; font-size: 0.9em; border-top: 1px solid #dee2e6; padding-top: 20px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ Аудит безпеки: {domain}</h1>
            <p><strong>Дата сканування:</strong> {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>Цільовий URL:</strong> <a href="{data['url']}" target="_blank">{data['url']}</a></p>

            <h2>1. Базова інформація</h2>
            <table>
                <tr><th>Параметр</th><th>Результат</th></tr>
                <tr><td>Відкриті порти</td><td>{ports_str}</td></tr>
                <tr><td>SSL Сертифікат</td><td>{ssl_status}</td></tr>
                <tr><td>Web Application Firewall (WAF)</td><td><strong>{waf_status}</strong></td></tr>
                <tr><td>Виявлені технології</td><td>{tech_str}</td></tr>
            </table>

            <h2>2. Карта сайту (DAST Attack Surface)</h2>
            <div class="crawler-list">
                <ul style="margin: 0;">
                    {crawler_html}
                </ul>
            </div>

            <h2>3. OSINT: Знайдені субдомени та Email</h2>
            <ul>
                <li><strong>Субдомени:</strong></li>
                <ul>{subdomains_html}</ul>
                <br>
                <li><strong>Витоки Email-адрес:</strong></li>
                <ul>{emails_html}</ul>
            </ul>

            <h2>4. HTTP Заголовки безпеки (OWASP A05)</h2>
            <table>
                <tr><th>Заголовок</th><th>Статус (CWE-693)</th></tr>
                {headers_html}
            </table>

            <h2>5. Виявлені вразливості (Параметри)</h2>
            {vulns_html}

            <h2>6. Приховані директорії (Brute-force)</h2>
            <ul>
                {dirs_html}
            </ul>

            <div class="footer">
                Згенеровано автоматично | Web Vulnerability Scanner (Навчальний проєкт)
            </div>
        </div>
    </body>
    </html>
    """
    
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html_content)
        
    return os.path.abspath(filename)