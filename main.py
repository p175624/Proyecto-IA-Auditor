import os
import json
import paramiko
import markdown
import time
from xhtml2pdf import pisa
from google import genai
from google.genai.errors import APIError
import re
from datetime import datetime
from dotenv import load_dotenv

# --- CARGAR VARIABLES DE ENTORNO ---
load_dotenv()

IP_VM = os.environ["SSH_HOST"]
USUARIO_SSH = os.environ["SSH_USER"]
RUTA_LLAVE = os.environ["SSH_KEY_PATH"]
RUTA_KNOWN_HOSTS = os.environ.get(
    "SSH_KNOWN_HOSTS_PATH",
    os.path.expanduser("~/.ssh/known_hosts")
)

# --- DICCIONARIO GLOBAL PARA SUSTITUCIÓN DE ANONIMIZACIÓN ---
_MAPEO_USUARIOS = {}
_CONTADOR_USUARIOS = 1

def anonimizar_usuario(nombre_real):
    """Sustituye nombres reales por seudónimos legibles preservando consistencia."""
    global _CONTADOR_USUARIOS
    # Evitamos anonimizar cuentas raíz del sistema críticas para el análisis
    if nombre_real in ["root", "daemon", "bin"]:
        return nombre_real
        
    if nombre_real not in _MAPEO_USUARIOS:
        _MAPEO_USUARIOS[nombre_real] = f"User_{_CONTADOR_USUARIOS}"
        _CONTADOR_USUARIOS += 1
    return _MAPEO_USUARIOS[nombre_real]

# --- FASE 1.5: PUERTOS (Optimizado con Regex) ---
def fase_1_5_extraer_puertos(ssh):
    print("  🔍  Escaneando puertos en escucha...")
    puertos_vistos = set()
    puertos = []

    try:
        # Probamos ss primero, si falla usamos netstat
        comando = "ss -tuln"
        stdin, stdout, stderr = ssh.exec_command(comando)
        salida = stdout.read().decode("utf-8")

        if "LISTEN" not in salida:
            comando = "netstat -tuln"
            stdin, stdout, stderr = ssh.exec_command(comando)
            salida = stdout.read().decode("utf-8")

        # Expresión regular para capturar el puerto al final de la dirección local (soporta IPv4 e IPv6)
        # Busca patrones como :22 o .22 en un entorno de red, aislando el número final antes de los espacios
        regex_puerto = re.compile(r'[:.](\d+)\s+\S+\s+LISTEN')

        for linea in salida.splitlines():
            match = regex_puerto.search(linea)
            if match:
                puerto = int(match.group(1))
                protocolo = "tcp" if "tcp" in linea.lower() else "udp"
                
                clave = (puerto, protocolo)
                if clave not in puertos_vistos:
                    puertos_vistos.add(clave)
                    puertos.append({
                        "puerto": puerto,
                        "protocolo": protocolo
                    })

    except Exception as e:
        print(f"  ❌  Error al escanear puertos: {e}")

    return puertos

# --- FASE 1: EXTRACCIÓN ---
class ConfirmarLlaveHostPolicy(paramiko.MissingHostKeyPolicy):
    """
    Política personalizada que advierte al usuario sobre llaves de host desconocidas
    y solicita confirmación explícita antes de guardarla en known_hosts.
    """
    def missing_host_key(self, client, hostname, key):
        print(f"\n  ┌─────────────────────────────────────────────────┐")
        print(f"  │  ⚠️   ADVERTENCIA DE SEGURIDAD — HOST DESCONOCIDO  │")
        print(f"  └─────────────────────────────────────────────────┘")
        print(f"  🖥️   Host       : {hostname}")
        print(f"  🔑  Tipo llave  : {key.get_name()}")
        print(f"  🔏  Huella (Hex): {key.get_fingerprint().hex()}")
        
        # Solicitar confirmación interactiva al usuario
        respuesta = input("\n  ❓  ¿Confiar en este host y continuar la auditoría? (s/n): ").strip().lower()
        
        if respuesta == 's':
            client._system_host_keys.add(hostname, key.get_name(), key)
            if client._host_keys_filename is not None:
                client.save_host_keys(client._host_keys_filename)
            print("  ✅  Llave aceptada y guardada en known_hosts. Continuando...\n")
            return
        else:
            print("  🚫  Conexión abortada por el usuario.")
            raise paramiko.SSHException(f"Conexión abortada por el usuario: Host {hostname} no verificado.")

def fase_1_extraer_datos():
    print("\n┌──────────────────────────────────────────────────────┐")
    print("│  📡  FASE 1 — Extracción de datos del servidor        │")
    print("└──────────────────────────────────────────────────────┘")
    ssh = paramiko.SSHClient()

    try:
        ssh.load_host_keys(RUTA_KNOWN_HOSTS)
    except FileNotFoundError:
        print(f"  ⚠️   known_hosts no encontrado en: {RUTA_KNOWN_HOSTS}")
    
    # Cambiado a AutoAddPolicy para despliegues de auditoría más ágiles
    # ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.set_missing_host_key_policy(ConfirmarLlaveHostPolicy())


    usuarios_encontrados = []

    try:
        llave = paramiko.Ed25519Key.from_private_key_file(RUTA_LLAVE)
        print(f"  🔐  Conectando a {IP_VM} como '{USUARIO_SSH}'...")
        ssh.connect(hostname=IP_VM, username=USUARIO_SSH, pkey=llave, timeout=10)
        print(f"  ✅  Conexión SSH establecida exitosamente.")

        puertos_abiertos = fase_1_5_extraer_puertos(ssh)
        print(f"  📋  Puertos detectados: {len(puertos_abiertos)}")

        print("  👤  Analizando cuentas de usuario (/etc/passwd)...")
        stdin, stdout, stderr = ssh.exec_command("cat /etc/passwd")
        salida = stdout.read().decode("utf-8")

        for linea in salida.splitlines():
            if not linea.strip() or linea.startswith("#"):
                continue

            datos = linea.split(":")
            if len(datos) < 7:
                continue

            nombre_real = datos[0]
            shell = datos[-1].strip()

            try:
                uid = int(datos[2])
            except ValueError:
                continue

            tiene_login = (
                not shell.endswith("nologin")
                and not shell.endswith("false")
            )

            # Filtramos para enfocarnos en cuentas de usuarios reales o interactivas
            if uid >= 1000 or tiene_login:
                usuarios_encontrados.append({
                    "usuario_anonimizado": anonimizar_usuario(nombre_real),
                    "uid": uid,
                    "shell": shell,
                    "tiene_login": tiene_login
                })

        print(f"  👥  Usuarios relevantes encontrados: {len(usuarios_encontrados)}")

        return {
            "metadata_auditoria": {
                "origen": "Script Python",
                "estandar": "CIS Benchmarks"
            },
            "servidor_auditado": {
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
        print(f"  ❌  Error durante la extracción: {e}")
        return None
    finally:
        ssh.close()
        print("  🔌  Conexión SSH cerrada.")

# --- FASE 2: IA --- IA (Optimizado con Estrategia de Reintentos para Horas Pico) ---
def fase_2_analizar_con_ia(datos_json):
    print("\n┌──────────────────────────────────────────────────────┐")
    print("│  🤖  FASE 2 — Análisis con Inteligencia Artificial    │")
    print("└──────────────────────────────────────────────────────┘")
    print("  ⏳  Enviando datos a Gemini 2.5 Flash, por favor espera...")
    client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])

    # Aplicamos el prompt robustecido con restricciones técnicas profesionales
    prompt = f"""
Rol: Eres un Consultor Senior en Ciberseguridad especializado en sistemas Linux.

Contexto: Analiza el siguiente JSON que contiene los datos extraídos de un servidor bajo auditoría. Los datos de usuarios han sido previamente anonimizados por sustitución para proteger la privacidad del sistema.

Restricción Crítica: Basa tu análisis única y exclusivamente en los datos proporcionados en el JSON. No asumas ni inventes la existencia de otros servicios, usuarios o vulnerabilidades que no estén explícitamente listados.

Objetivos de Análisis:
1. Detectar cuentas con acceso interactivo (shells válidas como /bin/bash).
2. Identificar configuraciones potencialmente inseguras en los usuarios de sistema.
3. Analizar la exposición de servicios en red mediante los puertos abiertos detectados.
4. Correlacionar riesgos (ej: servicios críticos expuestos junto a la presencia de múltiples usuarios activos).

Formato de Salida: Genera un reporte exclusivo en Markdown profesional utilizando la siguiente estructura:

1. Resumen Ejecutivo: Incluye un Score de Seguridad numérico del 0 al 100 (donde 100 es totalmente seguro), justificando la deducción de puntos. Traduce el estado técnico a un lenguaje comprensible para la toma de decisiones gerenciales.
2. Hallazgos Prioritarios: Lista de los problemas más críticos encontrados.
3. Tabla de Riesgos: Una tabla Markdown con las columnas: ID | Riesgo Detectado | Nivel de Impacto (Crítico/Alto/Medio/Bajo) | Descripción.
4. Recomendaciones Técnicas: Pasos de mitigación específicos utilizando comandos de terminal para entornos Linux (Debian/Ubuntu), encerrados en bloques de código adecuados.

Datos JSON a analizar:
{json.dumps(datos_json, indent=2)}
"""
    

    MAX_RETRIES = 3       # Número máximo de intentos antes de rendirse
    INITIAL_DELAY = 4     # Segundos a esperar tras el primer fallo
    
    for intento in range(1, MAX_RETRIES + 1):
        try:
            print(f"  ⏳  Enviando datos a Gemini... (Intento {intento}/{MAX_RETRIES})")
            
            response = client.models.generate_content(
                model="gemini-2.5-flash",
                contents=prompt
            )
            
            print("  ✅  ¡Análisis de IA completado con éxito!")
            return response.text

        except (APIError, Exception) as e:
            print(f"  ⚠️   El servicio de IA está experimentando alta demanda. (Detalle: {e})")
            
            if intento < MAX_RETRIES:
                delay = INITIAL_DELAY * (2 ** (intento - 1))
                print(f"  🔄  Reintentando en {delay} segundos...")
                time.sleep(delay)
            else:
                print()
                print("  ┌─────────────────────────────────────────────────────┐")
                print("  │  ❌  ERROR CRÍTICO — Conexión con Gemini fallida      │")
                print("  ├─────────────────────────────────────────────────────┤")
                print("  │  🌐  Los servidores de IA presentan saturación.       │")
                print("  │  💾  Resguarda tu archivo JSON e inténtalo más tarde. │")
                print("  └─────────────────────────────────────────────────────┘")
                print()
                
    return None

# --- FASE 3: PDF ---
def fase_3_generar_pdf(texto_markdown):
    print("\n┌──────────────────────────────────────────────────────┐")
    print("│  📄  FASE 3 — Generación del Reporte PDF              │")
    print("└──────────────────────────────────────────────────────┘")
    print("  ⚙️   Convirtiendo Markdown a HTML y compilando PDF...")
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

    nombre_md = nombre_archivo.replace(".pdf", ".md")
    with open(nombre_md, "w", encoding="utf-8") as f:
        f.write(texto_markdown)

    print(f"  📑  Reporte PDF      → {nombre_archivo}")
    print(f"  📝  Reporte Markdown → {nombre_md}")

# --- MAIN ---
if __name__ == "__main__":
    print()
    print("╔══════════════════════════════════════════════════════╗")
    print("║       🛡️  PIPELINE DE AUDITORÍA DE SEGURIDAD  🛡️       ║")
    print("║              Estándar: CIS Benchmarks                ║")
    print("╚══════════════════════════════════════════════════════╝")
    print()

    vars_requeridas = ["GEMINI_API_KEY", "SSH_HOST", "SSH_USER", "SSH_KEY_PATH"]
    faltantes = [v for v in vars_requeridas if not os.environ.get(v)]

    if faltantes:
        print(f"  ❌  Error: Faltan las siguientes variables de entorno:")
        for v in faltantes:
            print(f"       • {v}")
    else:
        print(f"  ✅  Variables de entorno verificadas correctamente.")
        datos = fase_1_extraer_datos()
        if datos:
            reporte = fase_2_analizar_con_ia(datos)
            fase_3_generar_pdf(reporte)
            print()
            print("╔══════════════════════════════════════════════════════╗")
            print("║          ✅  AUDITORÍA COMPLETADA CON ÉXITO           ║")
            print("╚══════════════════════════════════════════════════════╝")
            print()