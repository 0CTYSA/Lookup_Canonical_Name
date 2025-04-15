import dns.resolver
import socket
from urllib.parse import urlparse


def extract_domain(url):
    parsed = urlparse(url)
    domain = parsed.netloc if parsed.netloc else parsed.path.split('/')[0]
    return domain.split(':')[0]  # Elimina puertos (ej: dominio.com:8080)


def get_cname(domain):
    try:
        return [rdata.target.to_text() for rdata in dns.resolver.resolve(domain, 'CNAME')]
    except:
        return ["No CNAME"]


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
        "CNAME": get_cname(domain),
        "IPs": get_ips(domain),
        "PTRs": {}
    }

    # Obtener IPs de los CNAMEs (si existen)
    cname_ips = []
    for cname in data["CNAME"]:
        if cname != "No CNAME":
            cname_ips.extend(get_ips(cname))
    data["CNAME_IPs"] = cname_ips

    # Obtener PTRs de todas las IPs (dominio + CNAMEs)
    all_ips = data["IPs"] + cname_ips
    for ip in all_ips:
        if ip != "No IPs":
            data["PTRs"][ip] = get_ptr(ip)

    return data


def save_to_txt(domain, data):
    filename = f"{domain}_analysis.txt"
    with open(filename, 'w', encoding='utf-8') as file:  # ¡Aquí el fix!
        file.write(f"Análisis completo de: {domain}\n")
        file.write("=" * 50 + "\n")
        file.write(f"CNAME(s): {', '.join(data['CNAME'])}\n")
        file.write(f"IPs del dominio: {', '.join(data['IPs'])}\n")
        if data['CNAME_IPs']:
            file.write(f"IPs de los CNAMEs: {', '.join(data['CNAME_IPs'])}\n")
        file.write("\nRegistros PTR (DNS inverso):\n")
        for ip, ptr in data['PTRs'].items():
            file.write(f"- {ip} → {ptr}\n")  # Ahora funciona con "→"
    print(f"\n[+] Resultados guardados en: {filename}")


def main():
    print("\n" + "=" * 50)
    print("ANALIZADOR DNS CON CNAME, IPs Y PTRs")
    print("=" * 50 + "\n")
    urls = input(
        "Ingresa las URLs o dominios (separados por coma): ").split(',')

    for url in urls:
        url = url.strip()
        domain = extract_domain(url)
        print(f"\nAnalizando: {domain}...")
        data = analyze_domain(domain)
        save_to_txt(domain, data)


if __name__ == "__main__":
    main()
