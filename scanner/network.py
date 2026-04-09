import socket
import ssl

def scan_ports(hostname):
    """Сканує популярні порти на цільовому хості."""
    ports_to_scan = [21, 22, 80, 443, 3306, 8080]
    open_ports = []
    
    for port in ports_to_scan:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0) 
        result = sock.connect_ex((hostname, port))
        
        if result == 0:
            open_ports.append(port)
        sock.close()
        
    return open_ports

def check_ssl(hostname):
    """Отримує базову інформацію про SSL сертифікат."""
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert['issuer'])
                return f"Сертифікат дійсний. Виданий: {issuer.get('organizationName', 'Невідомо')}"
    except Exception as e:
        return f"Помилка або сертифікат відсутній/недійсний: {e}"
