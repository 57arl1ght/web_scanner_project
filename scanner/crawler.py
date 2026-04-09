import requests
from bs4 import BeautifulSoup
import urllib.parse

def crawl_site(base_url, max_pages=20):
    """
    Вебпавук (Crawler): автоматично проходить по сторінках сайту 
    та збирає унікальні внутрішні посилання (Attack Surface Mapping).
    Ліміт max_pages встановлено для запобігання нескінченному циклу.
    """
    visited = set()
    to_visit = [base_url]
    internal_links = set()
    
    
    parsed_base = urllib.parse.urlparse(base_url)
    base_domain = parsed_base.netloc

    while to_visit and len(internal_links) < max_pages:
        current_url = to_visit.pop(0)
        
        if current_url in visited:
            continue
            
        visited.add(current_url)
        
        try:
            
            response = requests.get(current_url, timeout=5)
            
            
            if 'text/html' not in response.headers.get('Content-Type', ''):
                continue
                
            soup = BeautifulSoup(response.text, 'html.parser')
            internal_links.add(current_url) 
            
            
            for link in soup.find_all('a', href=True):
                href = link['href']
                
                full_url = urllib.parse.urljoin(current_url, href)
                parsed_url = urllib.parse.urlparse(full_url)
                
                
                if parsed_url.netloc == base_domain and parsed_url.scheme in ['http', 'https']:
                    clean_url = full_url.split('#')[0]
                    
                    if clean_url not in visited and clean_url not in to_visit:
                        to_visit.append(clean_url)
                        
        except requests.RequestException:
            pass 
    return list(internal_links)
