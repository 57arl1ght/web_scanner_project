import urllib.parse
from scanner.network import scan_ports, check_ssl
from scanner.web import check_security_headers, detect_technologies
from scanner.vuln import scan_vulnerabilities
from report.generator import generate_txt_report
from scanner.directories import find_hidden_directories
from scanner.subdomains import find_subdomains

def get_hostname(url):
    """Отримує доменне ім'я з URL для мережевого сканування."""
    parsed = urllib.parse.urlparse(url)
    return parsed.netloc or parsed.path

def main():
    print("="*50)
    print("🛡️  Web Vulnerability Scanner (Навчальний проєкт)")
    print("="*50)
    
    target_url = input("Введіть URL для сканування (наприклад, http://example.com/page?id=1): ").strip()
    
    if not target_url.startswith("http"):
        print("Помилка: URL має починатися з http:// або https://")
        return

    hostname = get_hostname(target_url)
    
    print(f"\n[+] Початок сканування: {target_url}")
    print("[~] Збір даних... Це може зайняти кілька хвилин.\n")

   
    print("-> Сканування портів...")
    open_ports = scan_ports(hostname)
    
    print("-> Перевірка SSL...")
    ssl_info = check_ssl(hostname) if target_url.startswith("https") else "SSL не використовується (HTTP)"

    print("-> Пошук субдоменів...")
    subdomain_info = find_subdomains(hostname)

    print("-> Пошук прихованих директорій та файлів...")
    dir_info = find_hidden_directories(target_url)

    
    print("-> Перевірка заголовків безпеки...")
    headers_info = check_security_headers(target_url)
    
    print("-> Визначення технологій...")
    tech_info = detect_technologies(target_url)

   
    print("-> Сканування на базові вразливості (SQLi, XSS, Dir Traversal)...")
    vuln_info = scan_vulnerabilities(target_url)

    
    print("\n[+] Сканування завершено. Формування звіту...")
    report_data = {
        "url": target_url,
        "ports": open_ports,
        "ssl": ssl_info,
        "subdomains": subdomain_info,
        "headers": headers_info,
        "tech": tech_info,
        "vulns": vuln_info,
        "directories": dir_info
    }
    
    report_filename = generate_txt_report(report_data)
    print(f"[!] Звіт збережено у файл: {report_filename}")

if __name__ == "__main__":
    main()
