import requests
import urllib.parse
import concurrent.futures

def check_single_path(base_url, path):
    """Допоміжна функція для перевірки одного шляху."""
    target_url = urllib.parse.urljoin(base_url, path)
    try:
        # Робимо HEAD запит замість GET для швидкості (нам потрібен лише статус)
        response = requests.head(target_url, timeout=3, allow_redirects=False)
        
        # 200 - Знайдено, 403 - Доступ заборонено (але файл існує!), 301/302 - Перенаправлення
        if response.status_code in [200, 403, 301, 302]:
            return f"[+] Знайдено ({response.status_code}): {target_url}"
    except requests.RequestException:
        pass
    return None

def find_hidden_directories(url):
    """Шукає приховані адмін-панелі та чутливі файли за допомогою багатопотоковості."""
    results = []
    
    # Витягуємо базовий URL (щоб відкинути параметри типу ?id=1)
    parsed_url = urllib.parse.urlparse(url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}/"
    
    # Словник найпопулярніших чутливих шляхів (можна розширювати)
    wordlist = [
        "admin/", "administrator/", "login/", "wp-login.php", 
        "wp-admin/", "admin.php", "cpanel/", "phpmyadmin/", 
        "db/", "database.sql", "backup.zip", "backup.sql", 
        ".git/", ".env", "config.php", "config.bak", 
        "test/", "api/", "server-status", "robots.txt"
    ]
    
    # Використовуємо ThreadPoolExecutor для паралельного (швидкого) сканування
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        # Запускаємо перевірку для кожного шляху зі словника
        futures = [executor.submit(check_single_path, base_url, path) for path in wordlist]
        
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                results.append(result)
                
    if not results:
        results.append("Прихованих директорій або критичних файлів зі стандартного списку не знайдено.")
        
    return results