import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import urllib.parse
import webbrowser

# Імпортуємо наші модулі
from scanner.network import scan_ports, check_ssl
from scanner.web import check_security_headers, detect_technologies
from scanner.vuln import scan_vulnerabilities
from report.html_generator import generate_html_report
from scanner.directories import find_hidden_directories
from scanner.subdomains import find_subdomains
from scanner.waf import detect_waf
from scanner.osint import extract_emails
from scanner.crawler import crawl_site

class ScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Web Vulnerability Scanner - Навчальний проєкт")
        self.root.geometry("800x680")
        self.root.configure(padx=20, pady=20)

        self.url_frame = ttk.Frame(self.root)
        self.url_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(self.url_frame, text="Цільовий URL:").pack(side=tk.LEFT, padx=(0, 10))
        
        self.url_entry = ttk.Entry(self.url_frame, width=50)
        self.url_entry.pack(side=tk.LEFT, expand=True, fill=tk.X)
        self.url_entry.insert(0, "http://testphp.vulnweb.com/")
        
        # --- ІДЕАЛЬНЕ МЕНЮ ТА ОБРОБКА КЛАВІШ ---
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Вставити", command=self.paste_from_menu)
        self.context_menu.add_command(label="Очистити", command=self.clear_entry)
        
        self.url_entry.bind("<Button-3>", self.show_context_menu)
        # Прив'язуємо гарячі клавіші ТІЛЬКИ до поля вводу
        self.url_entry.bind("<Control-KeyPress>", self.keyboard_shortcuts)
        # ---------------------------------------

        self.scan_btn = ttk.Button(self.url_frame, text="Сканувати", command=self.start_scan)
        self.scan_btn.pack(side=tk.LEFT, padx=(10, 0))

        # --- БЛОК ЧЕКБОКСІВ ---
        self.options_frame = ttk.LabelFrame(self.root, text=" Вибір модулів для сканування ")
        self.options_frame.pack(fill=tk.X, pady=(0, 15), ipadx=10, ipady=5)

        self.var_waf = tk.BooleanVar(value=True)
        self.var_ports = tk.BooleanVar(value=True)
        self.var_ssl = tk.BooleanVar(value=True)
        self.var_headers = tk.BooleanVar(value=True)
        self.var_vulns = tk.BooleanVar(value=True)
        self.var_dirs = tk.BooleanVar(value=True)
        self.var_subs = tk.BooleanVar(value=True)
        self.var_emails = tk.BooleanVar(value=True)
        self.var_crawler = tk.BooleanVar(value=True)

        ttk.Checkbutton(self.options_frame, text="Виявлення WAF", variable=self.var_waf).grid(row=0, column=0, sticky=tk.W, padx=10, pady=5)
        ttk.Checkbutton(self.options_frame, text="Сканування портів", variable=self.var_ports).grid(row=0, column=1, sticky=tk.W, padx=10, pady=5)
        ttk.Checkbutton(self.options_frame, text="Перевірка SSL/TLS", variable=self.var_ssl).grid(row=0, column=2, sticky=tk.W, padx=10, pady=5)
        
        ttk.Checkbutton(self.options_frame, text="Заголовки та технології", variable=self.var_headers).grid(row=1, column=0, sticky=tk.W, padx=10, pady=5)
        ttk.Checkbutton(self.options_frame, text="Пошук вразливостей (SQLi, XSS)", variable=self.var_vulns).grid(row=1, column=1, sticky=tk.W, padx=10, pady=5)
        ttk.Checkbutton(self.options_frame, text="Пошук директорій", variable=self.var_dirs).grid(row=1, column=2, sticky=tk.W, padx=10, pady=5)
        
        ttk.Checkbutton(self.options_frame, text="Пошук субдоменів (OSINT)", variable=self.var_subs).grid(row=2, column=0, sticky=tk.W, padx=10, pady=5)
        ttk.Checkbutton(self.options_frame, text="Збір Email-адрес (OSINT)", variable=self.var_emails).grid(row=2, column=1, sticky=tk.W, padx=10, pady=5)
        ttk.Checkbutton(self.options_frame, text="Карта сайту (Вебпавук DAST)", variable=self.var_crawler).grid(row=2, column=2, sticky=tk.W, padx=10, pady=5)
        
        self.progress = ttk.Progressbar(self.root, mode='indeterminate')
        self.progress.pack(fill=tk.X, pady=(0, 10))

        self.log_area = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, state=tk.DISABLED, font=("Consolas", 10))
        self.log_area.pack(expand=True, fill=tk.BOTH)

    def paste_from_menu(self):
        try:
            self.url_entry.event_generate("<<Paste>>")
        except Exception:
            pass

    def clear_entry(self):
        self.url_entry.delete(0, tk.END)

    def show_context_menu(self, event):
        self.url_entry.focus_set()
        self.context_menu.tk_popup(event.x_root, event.y_root)

    def keyboard_shortcuts(self, event):
        # 86 - це апаратний код клавіші V (М на укр. розкладці) у Windows
        if getattr(event, 'keycode', 0) == 86:
            self.url_entry.event_generate("<<Paste>>")
            return "break" # Блокуємо стандартну поведінку, щоб не було подвійної вставки

    def log(self, message):
        self.log_area.config(state=tk.NORMAL)
        self.log_area.insert(tk.END, message + "\n")
        self.log_area.see(tk.END)
        self.log_area.config(state=tk.DISABLED)

    def start_scan(self):
        url = self.url_entry.get().strip()
        if not url.startswith("http"):
            messagebox.showerror("Помилка", "URL має починатися з http:// або https://")
            return

        self.scan_btn.config(state=tk.DISABLED)
        self.progress.start(10)
        self.log_area.config(state=tk.NORMAL)
        self.log_area.delete(1.0, tk.END)
        self.log_area.config(state=tk.DISABLED)

        threading.Thread(target=self.run_scan, args=(url,), daemon=True).start()

    def run_scan(self, target_url):
        self.log(f"[*] Початок сканування: {target_url}\n")
        
        parsed = urllib.parse.urlparse(target_url)
        hostname = parsed.netloc or parsed.path
        domain_only = parsed.netloc.split(':')[0]

        waf_info = "Пропущено користувачем"
        open_ports = None
        ssl_info = "Пропущено користувачем"
        headers_info = None
        tech_info = None
        vuln_info = None
        dir_info = None
        subdomains_info = None
        emails_info = None
        crawler_info = None

        try:
            if self.var_waf.get():
                self.log("-> Перевірка наявності WAF...")
                waf_info = detect_waf(target_url)
                self.log(f"   {waf_info}")

            if self.var_ports.get():
                self.log("-> Сканування портів...")
                open_ports = scan_ports(hostname)

            if self.var_ssl.get():
                self.log("-> Перевірка SSL...")
                ssl_info = check_ssl(hostname) if target_url.startswith("https") else "SSL не використовується"

            if self.var_crawler.get():
                self.log("-> Запуск Вебпавука (картування поверхні атаки)...")
                crawler_info = crawl_site(target_url)
                if crawler_info:
                    self.log(f"   Знайдено внутрішніх сторінок: {len(crawler_info)}")

            if self.var_headers.get():
                self.log("-> Перевірка заголовків безпеки та технологій...")
                headers_info = check_security_headers(target_url)
                tech_info = detect_technologies(target_url)

            if self.var_vulns.get():
                self.log("-> Пошук вразливостей (SQLi, XSS)...")
                vuln_info = scan_vulnerabilities(target_url)

            if self.var_dirs.get():
                self.log("-> Пошук прихованих директорій та адмін-панелей...")
                dir_info = find_hidden_directories(target_url)

            if self.var_subs.get():
                self.log("-> Пошук субдоменів (API + Brute-force)...")
                subdomains_info = find_subdomains(domain_only)

            if self.var_emails.get():
                self.log("-> Збір Email-адрес зі сторінки...")
                emails_info = extract_emails(target_url)

            self.log("\n[+] Сканування завершено! Формування звіту...")
            
            report_data = {
                "url": target_url,
                "waf": waf_info,
                "ports": open_ports,
                "ssl": ssl_info,
                "headers": headers_info,
                "tech": tech_info,
                "vulns": vuln_info,
                "directories": dir_info,
                "subdomains": subdomains_info,
                "emails": emails_info,
                "crawler": crawler_info
            }
            
            report_filepath = generate_html_report(report_data)
            self.log(f"\n[!] Успіх! Звіт збережено:\n{report_filepath}")
            
            self.root.after(0, lambda: self.show_success_and_open(report_filepath))

        except Exception as e:
            self.log(f"\n[!] Виникла помилка під час сканування: {e}")
            messagebox.showerror("Помилка", str(e))
            
        finally:
            self.progress.stop()
            self.scan_btn.config(state=tk.NORMAL)

    def show_success_and_open(self, filepath):
        if messagebox.askyesno("Готово", f"Сканування завершено!\n\nЗвіт збережено.\nВідкрити його у браузері зараз?"):
            webbrowser.open(f"file://{filepath}")

if __name__ == "__main__":
    root = tk.Tk()
    style = ttk.Style()
    if "clam" in style.theme_names():
        style.theme_use("clam")
    app = ScannerGUI(root)
    root.mainloop()