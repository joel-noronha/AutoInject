import nmap
import os
import socket
import threading
import smtplib
from email.mime.text import MIMEText
from datetime import datetime
import configparser
import schedule
import platform
import time
from jinja2 import Template
import json
import xmltodict
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

# Load configuration
config = configparser.ConfigParser()
config.read('config.ini')
log_file = config['DEFAULT']['log_file']
email = config['DEFAULT'].get('email', None)
password = config['DEFAULT'].get('password', None)
smtp_server = config['DEFAULT'].get('smtp_server', None)
smtp_port = config['DEFAULT'].get('smtp_port', None)
auth_password = config['DEFAULT'].get('auth_password', None)

# Define color variables
YELLOW = "\033[93m"
WHITE = "\033[97m"
CYAN = "\033[96m"
GREEN = "\033[92m"
RED = "\033[91m"
MAGENTA = "\033[95m"
RESET = "\033[0m"

# Log file setup
def log_message(message):
    with open(log_file, "a") as f:
        f.write(f"{datetime.now()} - {message}\n")

def header():
    title = """
 █████╗ ██╗    ██╗████████╗ ██████╗ ██╗   ██╗███╗   ██╗     ██╗███████╗ ██████╗████████╗
██╔══██╗██║    ██║╚══██╔══╝██╔═══██╗██║   ██║████╗  ██║     ██║██╔════╝██╔════╝╚══██╔══╝
███████║██║    ██║   ██║   ██║   ██║██║   ██║██╔██╗ ██║     ██║█████╗  ██║        ██║   
██╔══██║██║    ██║   ██║   ██║   ██║██║   ██║██║╚██╗██║██   ██║██╔══╝  ██║        ██║   
██║  ██║█████████║   ██║   ╚██████╔╝╚██████╔╝██║ ╚████║╚█████╔╝███████╗╚██████╗   ██║   
╚═╝  ╚═╝╚════════╝   ╚═╝    ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝ ╚════╝ ╚══════╝ ╚═════╝   ╚═╝   
Nmap & SQL injection automation tool < dP >
"""
    divider = "---------------------------------------------------------------------------------"
    print(RED + title + RESET)
    print(divider)

# Show header
header()

# Authentication
def authenticate():
    attempts = 3
    while attempts > 0:
        entered_password = input(YELLOW + "Enter password to access the tool: " + RESET)
        if entered_password == auth_password:
            print(GREEN + "Authentication successful!" + RESET)
            log_message("User authenticated successfully")
            return True
        else:
            attempts -= 1
            print(RED + f"Incorrect password. {attempts} attempts remaining." + RESET)
            log_message("Incorrect password attempt")
    print(RED + "Authentication failed. Exiting..." + RESET)
    log_message("User failed authentication")
    exit()

# Run authentication
authenticate()

def scan_ports(ip, scan_type='default'):
    nm = nmap.PortScanner()
    print(GREEN + f"[*] Scanning ports on {ip} using {scan_type} scan..." + RESET)
    log_message(f"Scanning ports on {ip} with {scan_type} scan")
    try:
        if scan_type == 'syn':
            nm.scan(ip, arguments='-sS')  # SYN scan
        elif scan_type == 'udp':
            nm.scan(ip, arguments='-sU')  # UDP scan
        elif scan_type == 'version':
            nm.scan(ip, arguments='-sV')  # Version detection scan
        else:
            nm.scan(ip)  # Default scan
    except KeyboardInterrupt:
        print(RED + "\n[!] Port scan interrupted by user." + RESET)
        log_message("Port scan interrupted by user")
        return
    except Exception as e:
        print(RED + f"[!] Error scanning ports: {str(e)}" + RESET)
        log_message(f"Error scanning ports: {str(e)}")
        return

    report = ""
    for host in nm.all_hosts():
        host_info = f"[*] Host : {host} ({nm[host].hostname()})\n"
        host_info += f"[*] State : {nm[host].state()}\n"
        for proto in nm[host].all_protocols():
            host_info += f"[*] Protocol : {proto}\n"
            lport = nm[host][proto].keys()
            for port in sorted(lport):
                port_state = nm[host][proto][port]['state']
                color = GREEN if port_state == 'open' else RED
                host_info += f"{color}[*] Port : {port} State : {port_state}{RESET}\n"
        report += host_info + "\n"

    with open(f"port_scan_{ip}.txt", "w") as f:
        f.write(report)
    generate_report("Port Scan", ip, report, formats=["json", "xml", "pdf"])
    log_message(f"Port scan completed for {ip}")
    print(report)


def scan_services(ip):
    print(GREEN + "[*] Scanning services on " + ip + RESET)
    log_message(f"Scanning services on {ip}")
    open_ports = []
    report = ""

    def scan_port(port):
        nonlocal report
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            try:
                service = socket.getservbyport(port)
            except:
                service = "unknown"
            report_line = f"[*] Port : {port} Service : {service}\n"
            report += report_line
            print(GREEN + report_line + RESET)
        sock.close()

    threads = []
    for port in range(1, 65536):
        thread = threading.Thread(target=scan_port, args=(port,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    with open(f"service_scan_{ip}.txt", "w") as f:
        f.write(report)
    generate_report("Service Scan", ip, report, formats=["json", "xml", "pdf"])
    log_message(f"Service scan completed for {ip}")

def sql_injection(url):
    print(GREEN + "[*] Scanning SQL injection vulnerabilities on " + url + RESET)
    log_message(f"Scanning SQL injection vulnerabilities on {url}")
    cookies = input(CYAN + "[*] Enter the cookies for the target site (if any): " + RESET)
    try:
        sqlmap_command = f"sqlmap -u {url} --forms --crawl=2"
        if cookies:
            sqlmap_command += f" --cookie=\"{cookies}\""
        os.system(sqlmap_command)
    except KeyboardInterrupt:
        print(RED + "\n[!] SQL injection scan interrupted by user." + RESET)
        log_message("SQL injection scan interrupted by user")
        return
    except Exception as e:
        print(RED + f"[!] Error scanning SQL injection vulnerabilities: {str(e)}" + RESET)
        log_message(f"Error scanning SQL injection vulnerabilities: {str(e)}")
        return


def nikto_scan(url):
    print(GREEN + "[*] Scanning web server vulnerabilities on " + url + RESET)
    log_message(f"Scanning web server vulnerabilities on {url}")
    try:
        report_file = f"nikto_scan_{url.replace('://', '_').replace('/', '_')}.txt"
        os.system(f"nikto -h {url} -o {report_file}")
        print(GREEN + f"[*] Nikto scan completed. Report saved to {report_file}" + RESET)
        log_message(f"Nikto scan completed for {url}. Report saved to {report_file}")
    except KeyboardInterrupt:
        print(RED + "\n[!] Nikto scan interrupted by user." + RESET)
        log_message("Nikto scan interrupted by user")
        return
    except Exception as e:
        print(RED + f"[!] Error scanning web server vulnerabilities with Nikto: {str(e)}" + RESET)
        log_message(f"Error scanning web server vulnerabilities with Nikto: {str(e)}")
        return

def generate_report(scan_type, target, results, formats=["json"]):
    if "json" in formats:
        generate_json_report(scan_type, target, results)
    if "xml" in formats:
        generate_xml_report(scan_type, target, results)
    if "pdf" in formats:
        generate_pdf_report(scan_type, target, results)

def generate_json_report(scan_type, target, results):
    json_data = {
        "scan_type": scan_type,
        "target": target,
        "results": results.strip().split("\n")
    }
    json_file = f"{scan_type.lower().replace(' ', '_')}_{target.replace('://', '_').replace('/', '_')}.json"
    with open(json_file, "w") as f:
        json.dump(json_data, f, indent=4)
    print(GREEN + f"[*] JSON report saved to {json_file}" + RESET)
    log_message(f"JSON report saved to {json_file}")

def clear_screen():
    if platform.system() == "Windows":
        os.system("cls")
    else:
        os.system("clear")

def generate_xml_report(scan_type, target, results):
    xml_data = {
        "scan": {
            "scan_type": scan_type,
            "target": target,
            "results": {
                "result": results.strip().split("\n")
            }
        }
    }
    xml_file = f"{scan_type.lower().replace(' ', '_')}_{target.replace('://', '_').replace('/', '_')}.xml"
    with open(xml_file, "w") as f:
        f.write(xmltodict.unparse(xml_data, pretty=True))
    print(GREEN + f"[*] XML report saved to {xml_file}" + RESET)
    log_message(f"XML report saved to {xml_file}")

def generate_pdf_report(scan_type, target, results):
    pdf_file = f"{scan_type.lower().replace(' ', '_')}_{target.replace('://', '_').replace('/', '_')}.pdf"
    c = canvas.Canvas(pdf_file, pagesize=letter)
    c.setLineWidth(.3)
    c.setFont('Helvetica', 12)
    c.drawString(30, 750, f"Scan Type: {scan_type}")
    c.drawString(30, 735, f"Target: {target}")
    c.drawString(30, 720, "Results:")
    text = c.beginText(30, 705)
    for line in results.strip().split("\n"):
        text.textLine(line)
    c.drawText(text)
    c.save()
    print(GREEN + f"[*] PDF report saved to {pdf_file}" + RESET)
    log_message(f"PDF report saved to {pdf_file}")

def scheduled_scan():
    ip = config['DEFAULT'].get('scheduled_ip', '127.0.0.1')
    scan_ports(ip)
    scan_services(ip)
    sql_injection(f"http://{ip}")
    nikto_scan(f"http://{ip}")

# Main loop
def main():
    while True:
        print(CYAN + "[+] What do you want to audit today?" + RESET)
        print("1. Port Scan")
        print("2. Service Scan")
        print("3. SQL Injection Tests")
        print("4. Web Server Scan with Nikto")
        print("5. Schedule a Scan")
        print("6. Exit the program")
        option = input(GREEN + "> " + RESET)
        if option == "1":
            # Step 1: Ask for IP or domain
            ip = input(CYAN + "[*] Enter the IP or domain to scan: " + RESET)
            
            # Step 2: Ask for the scan type
            print(CYAN + "[*] Select scan type:" + RESET)
            print("1. Default scan")
            print("2. SYN scan")
            print("3. UDP scan")
            print("4. Version scan")
            scan_type_option = input(GREEN + "> " + RESET)
            
            # Step 3: Map input to scan type
            scan_type_map = {
                "1": "default",
                "2": "syn",
                "3": "udp",
                "4": "version"
            }
            scan_type = scan_type_map.get(scan_type_option, "default")
            
            # Step 4: Perform the port scan with the selected scan type
            scan_ports(ip, scan_type)
            input("\nPress Enter to continue...")
            clear_screen()

            header()
        elif option == "2":
            ip = input(CYAN + "[*] Enter the IP or domain to scan: " + RESET)
            scan_services(ip)
            input("\nPress Enter to continue...")
            clear_screen()

            header()
        elif option == "3":
            url = input(CYAN + "[*] Enter the URL to perform SQL injection tests: " + RESET)
            sql_injection(url)
            input("\nPress Enter to continue...")
            clear_screen()

            header()
        elif option == "4":
            url = input(CYAN + "[*] Enter the URL for Nikto web server scan: " + RESET)
            nikto_scan(url)
            input("\nPress Enter to continue...")
            clear_screen()
            header()
        elif option == "5":
            time = input(CYAN + "[*] Enter the time to schedule the scan (HH:MM format): " + RESET)
            schedule.every().day.at(time).do(scheduled_scan)
            print(GREEN + f"[*] Scan scheduled at {time} every day." + RESET)
            log_message(f"Scan scheduled at {time} every day")
            input("\nPress Enter to continue...")
            clear_screen()
            header()
        elif option == "6":
            print(RED + "[*] Exiting program..." + RESET)
            print(GREEN + "[+] Happy hacking ;)" + RESET)
            log_message("Program exited by user")
            exit()
        else:
            print(RED + "[!] Invalid option." + RESET)
            log_message("Invalid option selected")

if __name__ == "__main__":
    # Run the main program loop in a separate thread
    main_thread = threading.Thread(target=main)
    main_thread.start()

    # Schedule scan loop
    while True:
        schedule.run_pending()
        time.sleep(1)
