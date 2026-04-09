import requests
import re

def extract_emails(url):
    """
    Сканує HTML-код сторінки та витягує всі знайдені email-адреси 
    за допомогою регулярних виразів.
    """
    try:
        response = requests.get(url, timeout=5)
        
        # Класичний регулярний вираз для пошуку email-адрес
        email_pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
        
        # Знаходимо всі збіги та видаляємо дублікати (за допомогою set)
        found_emails = set(re.findall(email_pattern, response.text))
        
        # Фільтруємо хибні спрацьовування (наприклад, картинки типу name@2x.png)
        valid_emails = [email for email in found_emails if not email.endswith(('.png', '.jpg', '.jpeg', '.gif', '.webp'))]
        
        return list(valid_emails)
    except requests.RequestException:
        return []