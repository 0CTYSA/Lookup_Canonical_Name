# 🔍 DNS Analyzer Seguro para SOC

Este script en Python permite realizar un análisis seguro de nombres de dominio (DNS) con el fin de identificar registros importantes como CNAME, IPs asociadas y registros PTR (reverse DNS). Está diseñado pensando en entornos de **Security Operations Center (SOC)**, donde la trazabilidad y seguridad son clave.

## 📌 Funcionalidades

- Extrae dominios a partir de URLs.
- Obtiene la cadena de registros **CNAME** (con control de profundidad y timeout).
- Resuelve las direcciones **IP** del dominio y de los CNAMEs.
- Realiza búsquedas inversas **PTR** para las IPs obtenidas.
- Guarda un reporte detallado por dominio analizado.
- Incluye pausas automáticas para evitar bloqueos por consultas masivas (anti-abuso).

---

## 📁 Estructura de Carpetas

Todos los reportes se guardan automáticamente en la carpeta:

```txt
dns_analysis_results/
```

---

## 🛠️ Requisitos

Este script utiliza bibliotecas estándar de Python y una externa:

- Python 3.x
- `dnspython` (para resolución DNS)

Puedes instalar la dependencia con:

```bash
pip install dnspython
```

---

## ▶️ Uso

Ejecuta el script desde la terminal:

```bash
python cname_lk.py
```

Luego pega las URLs o dominios (uno por línea) y escribe `done` cuando termines.

Ejemplo:

```txt
example.com
https://subdomain.google.com
done
```

---

## 📄 Ejemplo de Salida

Para cada dominio analizado, se genera un archivo `.txt` con formato similar a:

```txt
Análisis completo de: example.com
==================================================

[+] Cadena de CNAMEs:
Nivel 1: www.example.com

[+] IPs:
- Dominio original: 93.184.216.34
- IPs de CNAMEs: 93.184.216.34

[+] Registros PTR:
- 93.184.216.34 -> 93.184.216.34.ptr.example.net
```

---

## 🔐 Consideraciones de Seguridad

- Los nombres de archivo son sanitizados para evitar problemas de seguridad en el sistema de archivos.
- Se incluyen **pausas entre consultas** para evitar el sobreuso de los servicios DNS.
- El script maneja errores comunes como `NXDOMAIN`, `NoAnswer` y `Timeout` de forma controlada.

---
