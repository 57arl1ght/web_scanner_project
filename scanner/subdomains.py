"""
Модуль для пошуку субдоменів.

Ідея модуля проста:
1. Пасивний пошук через crt.sh:
   ми не звертаємося напряму до цільового сайту, а аналізуємо публічні
   Certificate Transparency logs. Якщо для субдомену колись випускався
   SSL-сертифікат, його ім'я часто можна знайти в цих логах.
2. Активний пошук (brute-force):
   перевіряємо набір популярних назв субдоменів і дивимося, чи резолвляться
   вони в IP-адресу через DNS.

Такий підхід добре підходить для навчального проєкту, тому що поєднує
пасивну та активну розвідку і при цьому не потребує платних API.
"""

import concurrent.futures
import socket
import urllib.parse

import requests



COMMON_SUBDOMAINS = [
    "www",
    "api",
    "dev",
    "test",
    "mail",
    "admin",
    "blog",
    "staging",
    "app",
    "portal",
    "beta",
    "cdn",
    "m",
    "shop",
]

CRTSH_URL = "https://crt.sh/"
REQUEST_TIMEOUT = 10
MAX_WORKERS = 10


def _normalize_domain(domain):
    """
    Приводить вхідне значення до нормального доменного імені.

    Функція дозволяє передати як чистий домен (`example.com`),
    так і повний URL (`https://example.com/login`).
    """
    if not domain:
        return ""

    normalized = domain.strip().lower()

    
    if "://" in normalized:
        parsed = urllib.parse.urlparse(normalized)
        normalized = parsed.netloc or parsed.path

    
    normalized = normalized.split("/", 1)[0]

   
    normalized = normalized.split(":", 1)[0]

    return normalized.strip(".")


def _extract_subdomains_from_crtsh(domain):
    """
    Пасивно збирає субдомени з Certificate Transparency logs через crt.sh.

    Логіка:
    - виконуємо запит до crt.sh у JSON-форматі;
    - читаємо поля `name_value`, де містяться доменні імена із сертифікатів;
    - відкидаємо wildcard-записи (`*.example.com`) та сам кореневий домен;
    - залишаємо лише ті записи, які справді належать до нашого домену.
    """
    found_subdomains = set()
    params = {
        "q": f"%.{domain}",
        "output": "json",
    }
    headers = {
        "User-Agent": "WebVulnerabilityScanner/1.0 (student project)",
    }

    try:
        response = requests.get(
            CRTSH_URL,
            params=params,
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        certificates = response.json()
    except (requests.RequestException, ValueError):
     
        return found_subdomains

    for certificate in certificates:
        name_value = certificate.get("name_value", "")

        
        for raw_name in name_value.splitlines():
            candidate = raw_name.strip().lower()

            if not candidate:
                continue

            
            if candidate.startswith("*."):
                candidate = candidate[2:]

           
            if candidate == domain:
                continue

            if candidate.endswith(f".{domain}"):
                found_subdomains.add(candidate)

    return found_subdomains


def _resolve_subdomain(subdomain):
    """
    Перевіряє, чи резолвиться субдомен у DNS.

    Якщо DNS-запис існує, `socket.getaddrinfo()` поверне інформацію
    про IP-адресу. Для навчального сканера цього достатньо, щоб вважати
    субдомен знайденим.
    """
    try:
        socket.getaddrinfo(subdomain, None)
        return subdomain
    except socket.gaierror:
        return None
    except OSError:
   
        return None


def _bruteforce_subdomains(domain, wordlist=None):
    """
    Активно перевіряє найпоширеніші імена субдоменів у кількох потоках.

    Приклад:
    - формуємо `api.example.com`, `dev.example.com`, `mail.example.com`;
    - кожен варіант паралельно відправляється на DNS-резолв;
    - якщо ім'я перетворюється в IP-адресу, додаємо його до результату.
    """
    found_subdomains = set()
    candidates = wordlist or COMMON_SUBDOMAINS

    if not candidates:
        return found_subdomains

    max_workers = min(MAX_WORKERS, len(candidates))

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(_resolve_subdomain, f"{prefix}.{domain}")
            for prefix in candidates
        ]

        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                found_subdomains.add(result)

    return found_subdomains


def find_subdomains(domain):
    """
    Повертає список унікальних знайдених субдоменів.

    Алгоритм роботи:
    1. Нормалізація вхідного значення.
    2. Пасивний збір через crt.sh.
    3. Активний brute-force для популярних назв.
    4. Об'єднання результатів без дублікатів і сортування.

    Параметр:
    - domain: домен або URL, наприклад `example.com` або `https://example.com`

    Повертає:
    - list[str]: список знайдених субдоменів
    """
    normalized_domain = _normalize_domain(domain)

    if not normalized_domain:
        return []

    found_subdomains = set()

   
    found_subdomains.update(_extract_subdomains_from_crtsh(normalized_domain))

   
    found_subdomains.update(_bruteforce_subdomains(normalized_domain))

    return sorted(found_subdomains)


__all__ = ["find_subdomains"]
