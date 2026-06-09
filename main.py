"""
================================================================================
SISTEMA DE AUDITORÍA DE SEGURIDAD PARA SERVIDORES LINUX (CIS BENCHMARKS)
================================================================================

Descripción General:
    Este script implementa un pipeline completo de auditoría de seguridad para
    servidores Linux (basado en estándares CIS). El sistema:

    1. Se conecta vía SSH al servidor objetivo
    2. Extrae información relevante (usuarios, puertos abiertos)
    3. Anonimiza los datos para proteger la privacidad
    4. Envía los datos a la API de Gemini (Google AI)
    5. Procesa la respuesta estructurada (JSON validado con Pydantic)
    6. Genera un reporte profesional en PDF y Markdown

Arquitectura de 3 Fases:
    - FASE 1: Extracción de datos del servidor remoto
    - FASE 1.5: Escaneo de puertos en escucha
    - FASE 2: Análisis inteligente con IA (Structured Outputs)
    - FASE 3: Generación de reporte PDF/Markdown

Requisitos de Variables de Entorno (.env):
    - GEMINI_API_KEY: API key de Google AI Studio
    - SSH_HOST: IP o hostname del servidor objetivo
    - SSH_USER: Usuario SSH para la conexión
    - SSH_KEY_PATH: Ruta a la llave privada SSH
    - SSH_KNOWN_HOSTS_PATH: (Opcional) Ruta a known_hosts

Autor: Script de Auditoría Automatizada
Versión: 2.0 (Con Structured Outputs)
Fecha: 2025
================================================================================
"""

# ============================================================================
# IMPORTACIÓN DE LIBRERÍAS
# ============================================================================
import os
import json
import paramiko                      # Cliente SSH para conexión remota
import markdown                      # Conversión de Markdown a HTML
import time                          # Para reintentos y delays
from xhtml2pdf import pisa           # Conversión de HTML a PDF
from google import genai             # Cliente oficial de Gemini API
from google.genai import types       # Tipos para configuración de API
from google.genai.errors import APIError  # Manejo de errores específicos
import re                            # Expresiones regulares (respaldo)
from datetime import datetime        # Timestamps para nombres de archivo
from dotenv import load_dotenv       # Carga de variables de entorno
from pydantic import BaseModel, Field  # Validación de esquemas de datos
from typing import List              # Type hints para listas

# ============================================================================
# CONFIGURACIÓN INICIAL
# ============================================================================
# Carga las variables definidas en el archivo .env
load_dotenv()

# Configuración de conexión SSH obtenida del entorno
IP_VM = os.environ["SSH_HOST"]
USUARIO_SSH = os.environ["SSH_USER"]
RUTA_LLAVE = os.environ["SSH_KEY_PATH"]
RUTA_KNOWN_HOSTS = os.environ.get(
    "SSH_KNOWN_HOSTS_PATH",
    os.path.expanduser("~/.ssh/known_hosts")  # Ruta por defecto
)
# Contraseña sudo para comandos privilegiados (opcional)
SUDO_PASSWORD = os.environ.get("SUDO_PASSWORD", "")

# ============================================================================
# SISTEMA DE ANONIMIZACIÓN DE USUARIOS
# ============================================================================
# Diccionario global que mapea nombres reales a seudónimos
# Objetivo: Cumplir con normativas de privacidad (GDPR, LOPD) preservando
# la capacidad de análisis contextual.
_MAPEO_USUARIOS = {}
_CONTADOR_USUARIOS = 1

def anonimizar_usuario(nombre_real):
    """
    Convierte un nombre de usuario real en un seudónimo legible y consistente.
    
    Mecanismo:
        - Usuarios del sistema (root, daemon, bin) mantienen su identidad
        - Usuarios reales se convierten en User_1, User_2, etc.
        - El mapeo es consistente durante toda la ejecución
    
    Args:
        nombre_real (str): Nombre original del usuario (ej: "juan.perez")
    
    Returns:
        str: Seudónimo anonimizado (ej: "User_1")
    """
    global _CONTADOR_USUARIOS
    
    # Los usuarios del sistema no requieren anonimización
    if nombre_real in ["root", "daemon", "bin"]:
        return nombre_real
    
    # Primera vez que vemos este usuario: crear nuevo seudónimo
    if nombre_real not in _MAPEO_USUARIOS:
        _MAPEO_USUARIOS[nombre_real] = f"User_{_CONTADOR_USUARIOS}"
        _CONTADOR_USUARIOS += 1
    
    return _MAPEO_USUARIOS[nombre_real]

# ============================================================================
# MODELOS DE DATOS ESTRUCTURADOS (Pydantic)
# ============================================================================
# Estos esquemas definen el contrato entre el script y la IA.
# Gemini debe responder EXACTAMENTE con esta estructura, garantizando
# que el reporte siempre se pueda generar sin errores de formato.

class RiesgoFila(BaseModel):
    """
    Representa una fila individual en la matriz de riesgos.
    
    Attributes:
        id_riesgo: Identificador único (R-01, R-02, etc.)
        riesgo_detectado: Título corto descriptivo del riesgo
        nivel_impacto: Categoría estricta (Crítico/Alto/Medio/Bajo)
        descripcion: Explicación técnica detallada
    """
    id_riesgo: str = Field(description="ID único del riesgo, ej: R-01, R-02")
    riesgo_detectado: str = Field(description="Título corto del riesgo encontrado")
    nivel_impacto: str = Field(description="Debe ser estrictamente uno de estos: Crítico, Alto, Medio o Bajo")
    descripcion: str = Field(description="Explicación detallada del riesgo técnico correlacionado o detectado")

class RecomendacionTecnica(BaseModel):
    """
    Describe una mitigación accionable para un problema específico.
    
    Attributes:
        titulo: Qué problema soluciona esta recomendación
        comandos: Lista de comandos Linux listos para copiar/pegar
        explicacion: Propósito y efecto de los comandos
    """
    titulo: str = Field(description="Qué problema soluciona la mitigación")
    comandos: List[str] = Field(description="Lista de comandos exactos de terminal Linux para entornos Debian/Ubuntu")
    explicacion: str = Field(description="Breve explicación de qué hace el comando o por qué se debe ejecutar")

class ReporteAuditoriaSchema(BaseModel):
    """
    Esquema completo del reporte de auditoría.
    
    Este es el contrato principal que la IA debe cumplir. Garantiza que
    el reporte final siempre tenga todas las secciones necesarias.
    
    Attributes:
        score_seguridad: Puntuación numérica 0-100 del estado general
        justificacion_score: Explicación ejecutiva de la puntuación
        resumen_ejecutivo: Traducción técnica a lenguaje gerencial
        hallazgos_prioritarios: Lista de los problemas más críticos
        tabla_riesgos: Lista de riesgos para la matriz tabular
        recomendaciones: Lista de mitigaciones técnicas
    """
    score_seguridad: int = Field(description="Valor numérico de evaluación general del servidor del 0 al 100")
    justificacion_score: str = Field(description="Breve explicación ejecutiva de por qué se dedujeron puntos")
    resumen_ejecutivo: str = Field(description="Traducción del estado técnico a un lenguaje comprensible para la toma de decisiones gerenciales")
    hallazgos_prioritarios: List[str] = Field(description="Lista de los problemas más críticos encontrados en el sistema")
    tabla_riesgos: List[RiesgoFila] = Field(description="Lista de objetos de riesgo que formarán las filas de la tabla")
    recomendaciones: List[RecomendacionTecnica] = Field(description="Lista de recomendaciones y mitigaciones técnicas detalladas")

# ============================================================================
# FASE 1.5: ESCANEO DE PUERTOS CON DETECCIÓN DE SERVICIOS
# ============================================================================
# Tabla de servicios conocidos para puertos comunes (fallback sin sudo)
_SERVICIOS_CONOCIDOS = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 67: "dhcp", 68: "dhcp-client", 69: "tftp", 80: "http",
    110: "pop3", 111: "rpcbind", 123: "ntp", 143: "imap", 161: "snmp",
    162: "snmp-trap", 179: "bgp", 389: "ldap", 443: "https", 445: "smb",
    465: "smtps", 514: "syslog", 587: "smtp-submission", 636: "ldaps",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
    2049: "nfs", 2375: "docker", 2376: "docker-tls", 3000: "app-dev",
    3306: "mysql", 3389: "rdp", 4369: "epmd", 5432: "postgresql",
    5601: "kibana", 5672: "amqp", 5900: "vnc", 6379: "redis",
    6443: "k8s-api", 7474: "neo4j", 8080: "http-alt", 8443: "https-alt",
    8888: "jupyter", 9000: "php-fpm", 9090: "prometheus", 9092: "kafka",
    9200: "elasticsearch", 9300: "elasticsearch-cluster",
    15672: "rabbitmq-mgmt", 27017: "mongodb",
}

def _ejecutar_sudo(ssh, comando):
    """
    Ejecuta un comando con sudo usando la contraseña del entorno.
    Devuelve (stdout_str, exito: bool).
    """
    if not SUDO_PASSWORD:
        return "", False
    cmd_sudo = f"echo '{SUDO_PASSWORD}' | sudo -S {comando} 2>/dev/null"
    _, stdout, stderr = ssh.exec_command(cmd_sudo)
    salida = stdout.read().decode("utf-8").strip()
    return salida, bool(salida)

def _detectar_servicio_puerto(ssh, puerto, protocolo):
    """
    Detecta el nombre del servicio que usa un puerto específico.

    Estrategia en cascada:
        1. ss -tlnp / ss -ulnp con sudo (muestra proceso dueño)
        2. lsof -i con sudo
        3. /etc/services como diccionario
        4. Tabla interna _SERVICIOS_CONOCIDOS
        5. "unknown" como último recurso

    Args:
        ssh: Conexión SSH activa
        puerto (int): Número de puerto
        protocolo (str): "tcp" o "udp"

    Returns:
        str: Nombre del servicio (ej: "ssh", "nginx", "postgresql")
    """
    flag_proto = "t" if protocolo == "tcp" else "u"

    # Intento 1: ss con sudo para obtener nombre del proceso
    salida_ss, ok = _ejecutar_sudo(ssh, f"ss -{flag_proto}lnp sport = :{puerto}")
    if ok and salida_ss:
        # Buscar patrón: users:(("nombre_proc",...))
        match = re.search(r'users:\(\("([^"]+)"', salida_ss)
        if match:
            return match.group(1).lower()

    # Intento 2: lsof con sudo
    salida_lsof, ok = _ejecutar_sudo(ssh, f"lsof -i {protocolo}:{puerto} -sTCP:LISTEN -nP")
    if ok and salida_lsof:
        lineas = salida_lsof.splitlines()
        if len(lineas) > 1:
            return lineas[1].split()[0].lower()  # Primera columna = nombre proceso

    # Intento 3: /etc/services (sin sudo)
    _, stdout, _ = ssh.exec_command(f"grep -w '{puerto}/{protocolo}' /etc/services 2>/dev/null | head -1")
    linea_svc = stdout.read().decode("utf-8").strip()
    if linea_svc:
        return linea_svc.split()[0].lower()

    # Intento 4: tabla interna
    if puerto in _SERVICIOS_CONOCIDOS:
        return _SERVICIOS_CONOCIDOS[puerto]

    return "unknown"

def fase_1_5_extraer_puertos(ssh):
    """
    Escanea los puertos en escucha en el servidor remoto e identifica
    el servicio o proceso que los utiliza.

    Metodología:
        1. Intenta usar 'ss' (socket statistics, más moderno)
        2. Fallback a 'netstat' si 'ss' no está disponible
        3. Filtra conexiones TCP en estado LISTEN
        4. Filtra conexiones UDP en estado UNCONN
        5. Elimina duplicados por (puerto, protocolo)
        6. Detecta el servicio/proceso por puerto (con sudo si está disponible)

    Args:
        ssh: Conexión SSH activa de paramiko

    Returns:
        list: Lista de diccionarios con:
              {'puerto': int, 'protocolo': str, 'servicio': str}
              Ejemplo: [{'puerto': 22, 'protocolo': 'tcp', 'servicio': 'sshd'}, ...]
    """
    print("  🔍  Escaneando puertos en escucha...")
    puertos_vistos = set()  # Control de duplicados
    puertos = []

    try:
        # Intento 1: Usar 'ss' (recomendado en sistemas modernos)
        _, stdout, _ = ssh.exec_command("ss -tuln 2>/dev/null")
        salida = stdout.read().decode("utf-8").strip()

        # Fallback a netstat si ss no devuelve nada útil
        if not salida or ("LISTEN" not in salida and "UNCONN" not in salida):
            _, stdout, _ = ssh.exec_command("netstat -tuln 2>/dev/null")
            salida = stdout.read().decode("utf-8").strip()

        # Procesar línea por línea
        for linea in salida.splitlines():
            partes = linea.split()
            if len(partes) < 5:
                continue

            proto_raw = partes[0].lower()
            estado = partes[1]

            # Filtros específicos por protocolo
            if proto_raw.startswith("tcp") and estado != "LISTEN":
                continue
            if proto_raw.startswith("udp") and estado not in ("UNCONN", "0.0.0.0:*", "*:*"):
                continue

            # Extraer el número de puerto (último componente después de ':')
            addr_local = partes[4] if len(partes) > 4 else partes[3]
            puerto_str = addr_local.rsplit(":", 1)[-1] if ":" in addr_local else addr_local.rsplit(".", 1)[-1]

            if not puerto_str.isdigit():
                continue

            puerto = int(puerto_str)
            protocolo = "udp" if proto_raw.startswith("udp") else "tcp"

            # Control de duplicados usando una tupla como clave
            clave = (puerto, protocolo)
            if clave not in puertos_vistos:
                puertos_vistos.add(clave)
                puertos.append({"puerto": puerto, "protocolo": protocolo})

    except Exception as e:
        print(f"  ❌  Error al escanear puertos: {e}")

    # Ordenar por protocolo y luego por número de puerto
    puertos.sort(key=lambda x: (x["protocolo"], x["puerto"]))

    # Detectar servicio para cada puerto encontrado
    print(f"  🔎  Identificando servicios en {len(puertos)} puerto(s)...")
    for entrada in puertos:
        servicio = _detectar_servicio_puerto(ssh, entrada["puerto"], entrada["protocolo"])
        entrada["servicio"] = servicio
        print(f"       {entrada['protocolo'].upper():3s}/{entrada['puerto']:<6d} → {servicio}")

    return puertos

# ============================================================================
# POLÍTICA PERSONALIZADA PARA VERIFICACIÓN DE HOSTS SSH
# ============================================================================
class ConfirmarLlaveHostPolicy(paramiko.MissingHostKeyPolicy):
    """
    Política personalizada para manejar hosts desconocidos en SSH.
    
    Comportamiento:
        - Muestra la huella digital (fingerprint) del host desconocido
        - Solicita confirmación interactiva al usuario
        - Si acepta: guarda la llave en known_hosts automáticamente
        - Si rechaza: aborta la conexión
    
    Esto mejora la seguridad al evitar ataques Man-in-the-Middle.
    """
    def missing_host_key(self, client, hostname, key):
        """
        Callback invocado cuando se encuentra un host no verificado.
        
        Args:
            client: Cliente SSH
            hostname: Nombre/IP del host remoto
            key: Llave pública del host remoto
        """
        print(f"\n  ┌─────────────────────────────────────────────────┐")
        print(f"  │  ⚠️   ADVERTENCIA DE SEGURIDAD — HOST DESCONOCIDO  │")
        print(f"  └─────────────────────────────────────────────────┘")
        print(f"  🖥️   Host       : {hostname}")
        print(f"  🔑  Tipo llave  : {key.get_name()}")
        print(f"  🔏  Huella (Hex): {key.get_fingerprint().hex()}")
        
        respuesta = input("\n  ❓  ¿Confiar en este host y continuar la auditoría? (s/n): ").strip().lower()
        
        if respuesta == 's':
            # Agregar y persistir la nueva llave
            client._system_host_keys.add(hostname, key.get_name(), key)
            if client._host_keys_filename is not None:
                client.save_host_keys(client._host_keys_filename)
            print("  ✅  Llave aceptada y guardada en known_hosts. Continuando...\n")
            return
        else:
            print("  🚫  Conexión abortada por el usuario.")
            raise paramiko.SSHException(f"Conexión abortada por el usuario: Host {hostname} no verificado.")

# ============================================================================
# FASE 1: EXTRACCIÓN DE DATOS DEL SERVIDOR
# ============================================================================
def fase_1_extraer_datos():
    """
    Establece conexión SSH y extrae información crítica del servidor.
    
    Información recolectada:
        - Usuarios del sistema (filtrados por UID >= 1000 o con shell de login)
        - Puertos abiertos y en escucha (TCP/UDP)
        - Metadatos de la auditoría
    
    La extracción es anónima: los nombres reales se convierten en seudónimos
    inmediatamente después de la lectura.
    
    Returns:
        dict | None: Diccionario estructurado con los datos extraídos,
                     o None si ocurre un error crítico.
    
    Estructura del retorno:
        {
            "metadata_auditoria": {...},
            "servidor_auditado": {...},
            "hallazgos_seguridad": {
                "usuarios": [{"usuario_anonimizado": "...", "uid": ..., ...}]
            },
            "superficie_expuesta": {
                "puertos_abiertos": [...]
            }
        }
    """
    print("\n┌──────────────────────────────────────────────────────┐")
    print("│  📡  FASE 1 — Extracción de datos del servidor        │")
    print("└──────────────────────────────────────────────────────┘")
    ssh = paramiko.SSHClient()

    # Cargar known_hosts existente si está disponible
    try:
        ssh.load_host_keys(RUTA_KNOWN_HOSTS)
    except FileNotFoundError:
        print(f"  ⚠️   known_hosts no encontrado en: {RUTA_KNOWN_HOSTS}")
    
    # Usar política interactiva para hosts desconocidos
    ssh.set_missing_host_key_policy(ConfirmarLlaveHostPolicy())
    usuarios_encontrados = []

    try:
        # Cargar la llave privada (Ed25519 recomendado para seguridad)
        llave = paramiko.Ed25519Key.from_private_key_file(RUTA_LLAVE)
        print(f"  🔐  Conectando a {IP_VM} como '{USUARIO_SSH}'...")
        ssh.connect(hostname=IP_VM, username=USUARIO_SSH, pkey=llave, timeout=10)
        print(f"  ✅  Conexión SSH establecida exitosamente.")

        # Escanear puertos abiertos
        puertos_abiertos = fase_1_5_extraer_puertos(ssh)
        print(f"  📋  Puertos detectados: {len(puertos_abiertos)}")

        # Extraer versión del sistema operativo
        print("  🖥️   Detectando sistema operativo y kernel...")
        info_so = {}

        # Nombre y versión del SO (/etc/os-release es estándar en systemd)
        _, stdout, _ = ssh.exec_command("cat /etc/os-release 2>/dev/null")
        os_release = stdout.read().decode("utf-8").strip()
        if os_release:
            for linea in os_release.splitlines():
                if linea.startswith("PRETTY_NAME="):
                    info_so["nombre"] = linea.split("=", 1)[1].strip().strip('"')
                elif linea.startswith("VERSION_ID="):
                    info_so["version_id"] = linea.split("=", 1)[1].strip().strip('"')
                elif linea.startswith("ID="):
                    info_so["distro"] = linea.split("=", 1)[1].strip().strip('"')

        # Fallback: lsb_release
        if not info_so.get("nombre"):
            _, stdout, _ = ssh.exec_command("lsb_release -d 2>/dev/null | cut -f2")
            lsb = stdout.read().decode("utf-8").strip()
            if lsb:
                info_so["nombre"] = lsb

        # Versión del kernel
        _, stdout, _ = ssh.exec_command("uname -r 2>/dev/null")
        kernel = stdout.read().decode("utf-8").strip()
        if kernel:
            info_so["kernel"] = kernel

        # Arquitectura
        _, stdout, _ = ssh.exec_command("uname -m 2>/dev/null")
        arch = stdout.read().decode("utf-8").strip()
        if arch:
            info_so["arquitectura"] = arch

        print(f"  ✅  SO: {info_so.get('nombre', 'desconocido')} | Kernel: {info_so.get('kernel', 'desconocido')}")

        # Extraer y procesar /etc/passwd
        print("  👤  Analizando cuentas de usuario (/etc/passwd)...")
        stdin, stdout, stderr = ssh.exec_command("cat /etc/passwd")
        salida = stdout.read().decode("utf-8")

        for linea in salida.splitlines():
            # Saltar líneas vacías o comentarios
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

            # Determinar si es una cuenta con capacidad de login interactivo
            tiene_login = (
                not shell.endswith("nologin")
                and not shell.endswith("false")
            )

            # Filtrar: solo usuarios con UID >= 1000 O capacidad de login
            if uid >= 1000 or tiene_login:
                usuarios_encontrados.append({
                    "usuario_anonimizado": anonimizar_usuario(nombre_real),
                    "uid": uid,
                    "shell": shell,
                    "tiene_login": tiene_login
                })

        print(f"  👥  Usuarios relevantes encontrados: {len(usuarios_encontrados)}")

        # Retornar datos estructurados
        return {
            "metadata_auditoria": {
                "origen": "Script Python",
                "estandar": "CIS Benchmarks"
            },
            "servidor_auditado": {
                "sistema_operativo": info_so.get("nombre", "desconocido"),
                "distro": info_so.get("distro", "desconocido"),
                "version_id": info_so.get("version_id", "desconocido"),
                "kernel": info_so.get("kernel", "desconocido"),
                "arquitectura": info_so.get("arquitectura", "desconocido")
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

# ============================================================================
# FASE 2: ANÁLISIS CON INTELIGENCIA ARTIFICIAL (GEMINI)
# ============================================================================
def fase_2_analizar_con_ia(datos_json):
    """
    Envía los datos extraídos a Gemini API para análisis y generación de reporte.
    
    Características clave:
        - Utiliza Structured Outputs (response_schema) para garantizar formato
        - Implementa reintentos exponenciales ante fallos de API
        - Temperatura baja (0.2) para respuestas consistentes y determinísticas
        - Prompt diseñado para evitar alucinaciones (basado solo en datos provistos)
    
    Args:
        datos_json (dict): Datos extraídos en la Fase 1
    
    Returns:
        str | None: JSON string que cumple con ReporteAuditoriaSchema,
                    o None si fallan todos los reintentos.
    """
    print("\n┌──────────────────────────────────────────────────────┐")
    print("│  🤖  FASE 2 — Análisis Estructurado con IA           │")
    print("└──────────────────────────────────────────────────────┘")
    
    client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])

    # Prompt diseñado para maximizar precisión y evitar invenciones
    prompt = f"""
Rol: Eres un Consultor Senior en Ciberseguridad especializado en sistemas Linux.

Contexto: Analiza el siguiente JSON que contiene los datos extraídos de un servidor bajo auditoría. Los datos de usuarios han sido previamente anonimizados por sustitución para proteger la privacidad del sistema.

Restricción Crítica: Basa tu análisis única y exclusivamente en los datos proporcionados en el JSON. No asumas ni inventes la existencia de otros servicios, usuarios o vulnerabilidades que no estén explícitamente listados.

Información del Servidor:
- Sistema Operativo: {datos_json.get("servidor_auditado", {}).get("sistema_operativo", "desconocido")}
- Kernel: {datos_json.get("servidor_auditado", {}).get("kernel", "desconocido")}
- Arquitectura: {datos_json.get("servidor_auditado", {}).get("arquitectura", "desconocido")}

Objetivos de Análisis:
1. Evaluar el estado del sistema operativo y kernel: ¿es una versión actualmente soportada? ¿hay kernels con CVEs públicos conocidos para esa versión?
2. Detectar cuentas con acceso interactivo (shells válidas como /bin/bash).
3. Identificar configuraciones potencialmente inseguras en los usuarios de sistema.
4. Analizar la exposición de servicios en red mediante los puertos abiertos detectados. Para cada puerto, considera tanto el número de puerto como el campo "servicio" que indica el proceso o daemon que lo utiliza.
5. Correlacionar riesgos: por ejemplo, servicios críticos expuestos (como bases de datos o paneles admin) junto a la presencia de múltiples usuarios activos, o versiones de kernel con vulnerabilidades conocidas combinadas con servicios expuestos.
6. Detectar servicios innecesarios o de alto riesgo según el contexto del servidor (ej: telnet, ftp, vnc, rdp).

Datos JSON a analizar:
{json.dumps(datos_json, indent=2)}
"""

    # Configuración de reintentos
    MAX_RETRIES = 4      # Número máximo de intentos
    INITIAL_DELAY = 4    # Delay inicial en segundos (se duplica cada intento)
    
    for intento in range(1, MAX_RETRIES + 1):
        try:
            print(f"  ⏳  Enviando consulta a Gemini... (Intento {intento}/{MAX_RETRIES})")
            
            # Llamada a la API con Structured Outputs
            # La magia ocurre aquí: Gemini debe responder con JSON que valide
            # contra ReporteAuditoriaSchema
            response = client.models.generate_content(
                model="gemini-2.5-flash",  # Modelo rápido y capaz
                contents=prompt,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                    response_schema=ReporteAuditoriaSchema,
                    temperature=0.2  # Baja temperatura = más determinístico
                )
            )
            
            print("  ✅  ¡Datos estructurados JSON devueltos por la IA correctamente!")
            return response.text

        except APIError as e:
            print(f"  ⚠️   Error en la API de Gemini. (Detalle: {e})")
        except Exception as e:
            print(f"  ⚠️   Error inesperado. (Detalle: {e})")
            
            # Reintento con backoff exponencial
            if intento < MAX_RETRIES:
                delay = INITIAL_DELAY * (2 ** (intento - 1))
                print(f"  🔄  Reintentando en {delay} segundos...")
                time.sleep(delay)
            
    # Si llegamos aquí, todos los intentos fallaron
    print("\n  ┌─────────────────────────────────────────────────────┐")
    print("  │  ❌  ERROR CRÍTICO — Conexión con Gemini fallida      │")
    print("  ├─────────────────────────────────────────────────────┤")
    print("  │  🌐  Los servidores de IA presentan saturación.       │")
    print("  │  💾  Resguarda tu archivo JSON e inténtalo más tarde. │")
    print("  └─────────────────────────────────────────────────────┘\n")
                
    return None

# ============================================================================
# FASE 3: GENERACIÓN DE REPORTES PDF Y MARKDOWN
# ============================================================================
def fase_3_generar_pdf(json_ia_texto):
    """
    Convierte el análisis estructurado de la IA en reportes PDF y Markdown.
    
    Flujo de trabajo:
        1. Parsear el JSON validado por Pydantic
        2. Construir el contenido Markdown programáticamente (control total)
        3. Convertir Markdown a HTML con extensiones (tablas, código)
        4. Aplicar estilos CSS profesionales
        5. Generar PDF usando xhtml2pdf
        6. Guardar también el Markdown original como respaldo
    
    Ventajas de este enfoque:
        - El formato es 100% controlado por Python (no depende de la IA)
        - El PDF siempre tendrá la misma estructura consistente
        - El Markdown sirve como auditoría del contenido generado
    
    Args:
        json_ia_texto (str): JSON string que cumple con ReporteAuditoriaSchema
    """
    print("\n┌──────────────────────────────────────────────────────┐")
    print("│  📄  FASE 3 — Generación del Reporte PDF              │")
    print("└──────────────────────────────────────────────────────┘")
    print("  ⚙️   Parseando JSON estructurado y construyendo HTML estable...")
    
    try:
        # Convertir string JSON a diccionario Python
        data = json.loads(json_ia_texto)
    except Exception as e:
        print(f"  ❌  Error de parseo en el JSON devuelto por la IA: {e}")
        return

    # ========================================================================
    # CONSTRUCCIÓN DEL MARKDOWN (ESTRUCTURA FIJA)
    # ========================================================================
    # No confiamos en la IA para el formato; construimos todo manualmente
    # para garantizar consistencia visual.
    
    md_texto = f"# Reporte Ejecutivo de Auditoría de Seguridad\n\n"
    
    # Sección 1: Resumen Ejecutivo y Score
    md_texto += f"## 1. Resumen Ejecutivo\n"
    md_texto += f"**Score de Seguridad General:** {data['score_seguridad']} / 100\n\n"
    md_texto += f"*Justificación del Score:* {data['justificacion_score']}\n\n"
    md_texto += f"### Evaluación Gerencial\n"
    md_texto += f"{data['resumen_ejecutivo']}\n\n"
    
    # Sección 2: Hallazgos Prioritarios (lista de viñetas)
    md_texto += f"## 2. Hallazgos Prioritarios\n"
    for hallazgo in data['hallazgos_prioritarios']:
        md_texto += f"- {hallazgo}\n"
    md_texto += "\n"
    
    # Sección 3: Matriz de Riesgos (tabla)
    md_texto += f"## 3. Matriz de Riesgos Detectados\n\n"
    md_texto += "| ID | Riesgo Detectado | Nivel de Impacto | Descripción |\n"
    md_texto += "| :--- | :--- | :--- | :--- |\n"
    for riesgo in data['tabla_riesgos']:
        md_texto += f"| {riesgo['id_riesgo']} | {riesgo['riesgo_detectado']} | {riesgo['nivel_impacto']} | {riesgo['descripcion']} |\n"
    md_texto += "\n"
    
    # Sección 4: Recomendaciones Técnicas (con código bash)
    md_texto += f"## 4. Recomendaciones Técnicas de Mitigación\n\n"
    for rec in data['recomendaciones']:
        md_texto += f"### 🛠️ {rec['titulo']}\n"
        md_texto += f"*{rec['explicacion']}*\n\n"
        md_texto += "```bash\n"
        for comando in rec['comandos']:
            md_texto += f"{comando}\n"
        md_texto += "```\n\n"

    # ========================================================================
    # CONVERSIÓN A HTML CON ESTILOS
    # ========================================================================
    # Convertir Markdown a HTML (habilitando tablas y código formateado)
    texto_html = markdown.markdown(md_texto, extensions=["tables", "fenced_code"])

    # CSS profesional para el reporte PDF
    estilos = """
    <style>
        body { font-family: Helvetica, Arial, sans-serif; color: #333; padding: 20px; }
        h1 { color: #1a365d; border-bottom: 2px solid #2b6cb0; padding-bottom: 8px; font-size: 24px; }
        h2 { color: #2b6cb0; margin-top: 25px; border-bottom: 1px solid #e2e8f0; padding-bottom: 4px; font-size: 18px; }
        h3 { color: #2d3748; margin-top: 15px; font-size: 14px; }
        table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        th { background-color: #2b6cb0; color: white; padding: 8px; font-size: 11px; text-align: left; font-weight: bold; }
        td { padding: 8px; border: 1px solid #e2e8f0; font-size: 11px; vertical-align: top; }
        tr:nth-child(even) { background-color: #f7fafc; }
        pre { background-color: #edf2f7; padding: 10px; border-left: 3px solid #4a5568; font-family: monospace; font-size: 10px; margin: 10px 0; }
        ul { margin-top: 5px; padding-left: 20px; }
        li { font-size: 12px; line-height: 1.5; margin-bottom: 4px; }
    </style>
    """

    # Ensamblar HTML final
    html_final = f"<html><head>{estilos}</head><body>{texto_html}</body></html>"

    # ========================================================================
    # GENERACIÓN DE ARCHIVOS
    # ========================================================================
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    nombre_archivo = f"Reporte_Auditoria_{timestamp}.pdf"

    # Generar PDF
    with open(nombre_archivo, "wb") as f:
        pisa.CreatePDF(html_final, dest=f)

    # Guardar también el Markdown como respaldo/auditoría
    nombre_md = nombre_archivo.replace(".pdf", ".md")
    with open(nombre_md, "w", encoding="utf-8") as f:
        f.write(md_texto)

    print(f"  📑  Reporte PDF Estabilizado → {nombre_archivo}")
    print(f"  📝  Reporte Markdown Guardado → {nombre_md}")

# ============================================================================
# PUNTO DE ENTRADA PRINCIPAL (MAIN)
# ============================================================================
if __name__ == "__main__":
    """
    Orquestador principal del pipeline de auditoría.
    
    Flujo de ejecución:
        1. Validar variables de entorno requeridas
        2. Ejecutar Fase 1 (extracción de datos)
        3. Si éxito: ejecutar Fase 2 (análisis con IA)
        4. Si éxito: ejecutar Fase 3 (generación de reportes)
        5. Mostrar mensaje de éxito o error según corresponda
    
    El script está diseñado para ser robusto: si cualquier fase falla,
    se aborta gracefulmente con mensajes claros.
    """
    print()
    print("╔══════════════════════════════════════════════════════╗")
    print("║       🛡️  PIPELINE DE AUDITORÍA DE SEGURIDAD  🛡️       ║")
    print("║       Estándar: CIS — Con Salidas Estructuradas       ║")
    print("╚══════════════════════════════════════════════════════╝")
    print()

    # Verificar que todas las variables de entorno necesarias estén presentes
    vars_requeridas = ["GEMINI_API_KEY", "SSH_HOST", "SSH_USER", "SSH_KEY_PATH"]
    faltantes = [v for v in vars_requeridas if not os.environ.get(v)]

    if faltantes:
        print(f"  ❌  Error: Faltan las siguientes variables de entorno:")
        for v in faltantes:
            print(f"       • {v}")
    else:
        print(f"  ✅  Variables de entorno verificadas correctamente.")
        if SUDO_PASSWORD:
            print(f"  🔑  SUDO_PASSWORD detectado — detección de servicios con privilegios habilitada.")
        else:
            print(f"  ⚠️   SUDO_PASSWORD no configurado — la detección de servicios usará métodos sin privilegios.")
        
        # Ejecutar pipeline
        datos = fase_1_extraer_datos()
        if datos:
            reporte_json = fase_2_analizar_con_ia(datos)
            if reporte_json:
                fase_3_generar_pdf(reporte_json)
                print()
                print("╔══════════════════════════════════════════════════════╗")
                print("║          ✅  AUDITORÍA COMPLETADA CON ÉXITO           ║")
                print("╚══════════════════════════════════════════════════════╝")
                print()
        else:
            print("\n  ⛔  Proceso interrumpido: error en las capas de datos.")