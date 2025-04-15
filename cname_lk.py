import dns.resolver
import socket
from urllib.parse import urlparse


def extract_domain(url):
    parsed = urlparse(url)
    domain = parsed.netloc if parsed.netloc else parsed.path.split('/')[0]
    return domain.split(':')[0]


def get_cname(domain, max_depth=5):
    cnames = []
    current_domain = domain
    depth = 0

    while depth < max_depth:
        try:
            answer = dns.resolver.resolve(current_domain, 'CNAME')
            cname = answer[0].target.to_text().rstrip('.')
            cnames.append(cname)
            current_domain = cname  # Seguimos la cadena
            depth += 1
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            break
        except Exception as e:
            print(f"Error al resolver CNAME para {current_domain}: {e}")
            break

    return cnames if cnames else ["No CNAME"]


def get_ips(domain):
    try:
        return socket.gethostbyname_ex(domain)[2]
    except:
        return ["No IPs"]


def get_ptr(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "No PTR"


def analyze_domain(domain):
    data = {
        "Domain": domain,
        "CNAME_Chain": get_cname(domain),
        "IPs": get_ips(domain),
        "PTRs": {},
        "All_IPs": []
    }

    # Obtener IPs de todos los CNAMEs en la cadena
    cname_ips = []
    for cname in data["CNAME_Chain"]:
        if cname != "No CNAME":
            cname_ips.extend(get_ips(cname))
    data["All_IPs"] = list(set(data["IPs"] + cname_ips))  # Eliminar duplicados

    # Obtener PTRs de todas las IPs
    for ip in data["All_IPs"]:
        if ip != "No IPs":
            data["PTRs"][ip] = get_ptr(ip)

    return data


def save_to_txt(domain, data):
    filename = f"{domain}_analysis.txt"
    with open(filename, 'w', encoding='utf-8') as file:
        file.write(f"Análisis completo de: {domain}\n")
        file.write("=" * 50 + "\n")
        file.write(f"Cadena de CNAMEs:\n")
        for i, cname in enumerate(data["CNAME_Chain"], 1):
            file.write(f"Nivel {i}: {cname}\n")
        file.write(f"\nIPs del dominio: {', '.join(data['IPs'])}\n")
        if len(data["CNAME_Chain"]) > 1:
            file.write(
                f"IPs de todos los CNAMEs: {', '.join(data['All_IPs'])}\n")
        file.write("\nRegistros PTR (DNS inverso):\n")
        for ip, ptr in data["PTRs"].items():
            file.write(f"- {ip} → {ptr}\n")
    print(f"\n[+] Resultados guardados en: {filename}")


def main():
    print("\n" + "=" * 50)
    print("ANALIZADOR DNS CON CADENA DE CNAMEs RECURSIVOS")
    print("=" * 50 + "\n")
    urls = input(
        "Ingresa las URLs o dominios (separados por coma): ").split(',')

    for url in urls:
        url = url.strip()
        if not url:
            continue
        domain = extract_domain(url)
        print(f"\nAnalizando: {domain}...")
        data = analyze_domain(domain)
        save_to_txt(domain, data)


if __name__ == "__main__":
    main()
