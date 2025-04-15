import dns.resolver
import socket
from urllib.parse import urlparse
import ipaddress
import os
from datetime import datetime

# Configuración inicial
RESULTS_DIR = "dns_analysis_results"
os.makedirs(RESULTS_DIR, exist_ok=True)


def is_ip(address):
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False


def extract_domain(url):
    parsed = urlparse(url)
    domain = parsed.netloc if parsed.netloc else parsed.path.split('/')[0]
    return domain.split(':')[0]


def get_cname(domain, max_depth=5, timeout=5):
    cnames = []
    current_domain = domain
    depth = 0
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    while depth < max_depth:
        try:
            if is_ip(current_domain):
                break
            answer = resolver.resolve(current_domain, 'CNAME')
            cname = answer[0].target.to_text().rstrip('.')
            if cname in cnames:
                break
            cnames.append(cname)
            current_domain = cname
            depth += 1
        except dns.resolver.NoAnswer:
            break
        except dns.resolver.NXDOMAIN:
            break
        except dns.resolver.Timeout:
            return cnames if cnames else [f"Error: Timeout al resolver CNAME para {current_domain}"]
        except Exception as e:
            return cnames if cnames else [f"Error al resolver CNAME para {current_domain}: {str(e)}"]
    return cnames if cnames else ["No CNAME"]


def get_ips(domain, timeout=5):
    try:
        if is_ip(domain):
            return [domain]
        return list(set(socket.gethostbyname_ex(domain)[2]))
    except socket.gaierror:
        return ["No IPs (Error de resolución)"]
    except Exception as e:
        return [f"Error al resolver IPs: {str(e)}"]


def get_ptr(ip, timeout=5):
    try:
        if not is_ip(ip):
            return "No es una IP válida"
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "No PTR encontrado"
    except Exception as e:
        return f"Error en PTR: {str(e)}"


def analyze_domain(domain):
    data = {
        "Domain": domain,
        "CNAME_Chain": get_cname(domain),
        "IPs": get_ips(domain),
        "PTRs": {},
        "All_IPs": []
    }

    cname_ips = []
    for cname in data["CNAME_Chain"]:
        if not cname.startswith(("Error", "No CNAME")):
            cname_ips.extend(get_ips(cname))
    data["All_IPs"] = list(set(data["IPs"] + cname_ips))

    for ip in data["All_IPs"]:
        if is_ip(ip) and not ip.startswith("Error"):
            data["PTRs"][ip] = get_ptr(ip)

    return data


def save_to_txt(domain, data):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{RESULTS_DIR}/{domain}_analysis_{timestamp}.txt"
    with open(filename, 'w', encoding='utf-8') as file:
        file.write(f"Análisis completo de: {domain}\n")
        file.write("=" * 50 + "\n")

        file.write("\n[+] Cadena de CNAMEs:\n")
        for i, cname in enumerate(data["CNAME_Chain"], 1):
            file.write(f"Nivel {i}: {cname}\n")

        file.write("\n[+] IPs:\n")
        file.write(f"- Dominio original: {', '.join(data['IPs'])}\n")
        if len(data["CNAME_Chain"]) > 1:
            file.write(f"- IPs de CNAMEs: {', '.join(data['All_IPs'])}\n")

        file.write("\n[+] Registros PTR:\n")
        for ip, ptr in data["PTRs"].items():
            file.write(f"- {ip} -> {ptr}\n")

    print(f"[+] Reporte guardado en: {filename}")


def main():
    print("\n" + "=" * 50)
    print("ANALIZADOR DNS BULK (Escribe 'done' para finalizar)")
    print("=" * 50 + "\n")
    print("Pega las URLs o dominios (uno por línea):")

    urls = []
    while True:
        line = input().strip()
        if line.lower() == 'done':
            break
        if line:
            urls.append(line)

    for url in urls:
        domain = extract_domain(url)
        print(f"\nAnalizando: {domain}...")
        data = analyze_domain(domain)
        save_to_txt(domain, data)

    print("\n[+] Análisis completado. Todos los resultados están en la carpeta 'dns_analysis_results'.")


if __name__ == "__main__":
    main()
