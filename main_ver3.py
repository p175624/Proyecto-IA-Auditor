import os
import json
import paramiko
import markdown
from xhtml2pdf import pisa
from google import genai
import hashlib
from datetime import datetime  # FIX: para timestamp en nombre del PDF

# --- CONFIGURACIÓN ---
IP_VM = "IP_DE_SERVIDOR_A_AUDITAR"
USUARIO_SSH = "USUARIO_AUTORIZADO"
RUTA_LLAVE = r"\ruta_a_llave\id_ed25519"
RUTA_KNOWN_HOSTS = os.path.expanduser("~/.ssh/known_hosts")  # FIX: para RejectPolicy

# --- FUNCIONES DE SEGURIDAD ---
def anonimizar(texto):
    return hashlib.sha256(texto.encode()).hexdigest()

# --- FASE 1.5: PUERTOS ---
def fase_1_5_extraer_puertos(ssh):
    print("[*] Extrayendo puertos abiertos...")

    # FIX: usar set para evitar duplicados IPv4/IPv6
    puertos_vistos = set()
    puertos = []

    try:
        comando = "ss -tuln"
        stdin, stdout, stderr = ssh.exec_command(comando)
        salida = stdout.read().decode("utf-8")

        if not salida.strip():
            comando = "netstat -tuln"
            stdin, stdout, stderr = ssh.exec_command(comando)
            salida = stdout.read().decode("utf-8")

        for linea in salida.splitlines():
            if "LISTEN" not in linea:
                continue

            partes = linea.split()
            if len(partes) <= 4:
                continue

            direccion = partes[4]
            if ":" not in direccion:
                continue

            puerto_str = direccion.split(":")[-1]

            try:
                puerto = int(puerto_str)
            except ValueError:  # FIX: solo capturar la excepción esperada
                continue

            clave = (puerto, partes[0])
            if clave in puertos_vistos:  # FIX: deduplicar
                continue

            puertos_vistos.add(clave)
            puertos.append({
                "puerto": puerto,
                "protocolo": partes[0]
            })

    except Exception as e:
        print(f"[-] Error extrayendo puertos: {e}")

    return puertos

# --- FASE 1: EXTRACCIÓN ---
def fase_1_extraer_datos():
    print("\n[*] FASE 1: Extrayendo datos del servidor...")

    ssh = paramiko.SSHClient()

    # FIX: RejectPolicy en lugar de AutoAddPolicy para evitar ataques MITM
    try:
        ssh.load_host_keys(RUTA_KNOWN_HOSTS)
    except FileNotFoundError:
        print(f"[-] Advertencia: no se encontró {RUTA_KNOWN_HOSTS}. Agrega el host manualmente con ssh-keyscan.")
    ssh.set_missing_host_key_policy(paramiko.RejectPolicy())

    usuarios_encontrados = []

    try:
        llave = paramiko.Ed25519Key.from_private_key_file(RUTA_LLAVE)
        ssh.connect(hostname=IP_VM, username=USUARIO_SSH, pkey=llave, timeout=10)

        puertos_abiertos = fase_1_5_extraer_puertos(ssh)

        stdin, stdout, stderr = ssh.exec_command("cat /etc/passwd")
        salida = stdout.read().decode("utf-8")

        for linea in salida.splitlines():
            if not linea.strip():
                continue

            datos = linea.split(":")
            if len(datos) < 7:
                continue

            nombre_real = datos[0]
            shell = datos[-1]

            try:
                uid = int(datos[2])
            except ValueError:
                continue

            tiene_login = (
                not shell.endswith("nologin")
                and not shell.endswith("false")
            )

            if uid >= 1000 or tiene_login:
                usuarios_encontrados.append({
                    "usuario_hash": anonimizar(nombre_real),
                    "uid": uid,
                    "shell": shell,
                    "tiene_login": tiene_login
                })

        return {
            "metadata_auditoria": {
                "origen": "Script Python",
                "estandar": "CIS Benchmarks"
            },
            "servidor_auditado": {
                # FIX: IP también anonimizada antes de enviar a la IA
                "ip_hash": anonimizar(IP_VM),
                "sistema_operativo": "Ubuntu Server"
            },
            "hallazgos_seguridad": {
                "modulo": "Control de Cuentas",
                "total_usuarios": len(usuarios_encontrados),
                "usuarios": usuarios_encontrados
            },
            "superficie_expuesta": {
                "total_puertos": len(puertos_abiertos),
                "puertos_abiertos": puertos_abiertos
            }
        }

    except Exception as e:
        print(f"[-] Error en extracción: {e}")
        return None

    finally:
        ssh.close()
        print("[*] Conexión SSH cerrada.")

# --- FASE 2: IA ---
def fase_2_analizar_con_ia(datos_json):
    print("[*] FASE 2: Analizando con IA...")

    client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])

    prompt = f"""
Eres un Consultor Senior en Ciberseguridad especializado en sistemas Linux.

Analiza el siguiente JSON que contiene:
- Usuarios del sistema (anonimizados)
- Puertos abiertos detectados

Objetivos:
- Detectar cuentas con acceso interactivo
- Identificar configuraciones inseguras
- Analizar la exposición de servicios en red
- Correlacionar riesgos (ej: SSH abierto + múltiples usuarios)

Genera un reporte en Markdown profesional con:
1. Resumen Ejecutivo con score de seguridad
2. Hallazgos prioritarios
3. Tabla de riesgos
4. Recomendaciones técnicas con comandos

JSON:
{json.dumps(datos_json, indent=2)}
"""

    response = client.models.generate_content(
        model="gemini-3.5-flash",  # OK: modelo confirmado como válido
        contents=prompt
    )

    return response.text

# --- FASE 3: PDF ---
def fase_3_generar_pdf(texto_markdown):
    print("[*] FASE 3: Generando PDF...")

    # FIX: nombre de archivo con timestamp para evitar sobreescribir reportes anteriores
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    nombre_archivo = f"Reporte_Auditoria_{timestamp}.pdf"

    texto_html = markdown.markdown(texto_markdown, extensions=["tables", "fenced_code"])

    estilos = """
    <style>
        body { font-family: Helvetica, Arial, sans-serif; color: #333; padding: 20px; }
        h1 { color: #1a365d; border-bottom: 2px solid #2b6cb0; padding-bottom: 8px; }
        h2 { color: #2b6cb0; margin-top: 20px; border-bottom: 1px solid #e2e8f0; }
        table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        th { background-color: #2b6cb0; color: white; padding: 8px; font-size: 12px; }
        td { padding: 8px; border: 1px solid #e2e8f0; font-size: 11px; }
        tr:nth-child(even) { background-color: #f7fafc; }
        pre { background-color: #edf2f7; padding: 10px; border-left: 3px solid #4a5568; font-family: monospace; font-size: 10px; }
    </style>
    """

    html_final = f"<html><head>{estilos}</head><body>{texto_html}</body></html>"

    with open(nombre_archivo, "wb") as f:
        pisa.CreatePDF(html_final, dest=f)

    # FIX: también guardar el markdown como archivo .md para auditoría
    nombre_md = nombre_archivo.replace(".pdf", ".md")
    with open(nombre_md, "w", encoding="utf-8") as f:
        f.write(texto_markdown)

    print(f"[+] Reporte PDF:      {nombre_archivo}")
    print(f"[+] Reporte Markdown: {nombre_md}")

# --- MAIN ---
if __name__ == "__main__":
    if not os.environ.get("GEMINI_API_KEY"):
        print("[-] Error: Configura la variable de entorno GEMINI_API_KEY.")
    else:
        datos = fase_1_extraer_datos()
        if datos:
            reporte = fase_2_analizar_con_ia(datos)
            fase_3_generar_pdf(reporte)
