# 🛡️ Linux Security Auditor - CIS Benchmark Pipeline

[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![Gemini AI](https://img.shields.io/badge/Gemini%20AI-4285F4?logo=googlecloud&logoColor=white)](https://deepmind.google/technologies/gemini/)

> **Pipeline automatizado de auditoría de seguridad para servidores Linux basado en estándares CIS Benchmarks, con análisis inteligente mediante Google Gemini AI, detección de servicios por puerto, y generación de reportes profesionales en PDF.**

```mermaid
flowchart TB
    subgraph INPUT["📥 ENTRADA Y CONFIGURACIÓN"]
        A1["🔧 Variables de entorno<br/>• GEMINI_API_KEY<br/>• SSH_HOST, SSH_USER<br/>• SSH_KEY_PATH<br/>• SUDO_PASSWORD (opcional)"]
        A2["✅ Validación<br/>Verificación de vars requeridas"]
    end

    subgraph CONNECTION["🔐 CONEXIÓN SSH"]
        B1["🔑 Autenticación<br/>Ed25519 desde archivo"]
        B2["⚠️ Verificación host<br/><b>ConfirmarLlaveHostPolicy</b><br/>• Muestra huella digital<br/>• Solicita confirmación<br/>• Guarda en known_hosts"]
    end

    subgraph EXTRACTION["📡 FASE 1: EXTRACCIÓN DE DATOS"]
        C1["🖥️ Información del SO<br/>• /etc/os-release<br/>• lsb_release -d<br/>• uname -r / uname -m"]
        C2["👤 Cuentas de usuario<br/>cat /etc/passwd<br/>Filtro: UID ≥ 1000 OR shell válida"]
        C3["🔐 Anonimización<br/>User_1, User_2...<br/>root/daemon/bin exentos"]
    end

    subgraph PORTS["🔍 FASE 1.5: PUERTOS Y SERVICIOS"]
        D1["📡 Escaneo de puertos<br/>ss -tuln → fallback netstat"]
        D2["🎯 Detección de servicios<br/><b>Estrategia en cascada:</b><br/>1. ss con sudo (proceso dueño)<br/>2. lsof con sudo<br/>3. /etc/services<br/>4. Tabla _SERVICIOS_CONOCIDOS<br/>5. unknown"]
        D3["📋 Resultado por puerto<br/>{puerto, protocolo, servicio}<br/>Ej: 22/tcp → sshd"]
    end

    subgraph DATA["💾 DATOS ESTRUCTURADOS"]
        E1["metadata_auditoria<br/>servidor_auditado<br/>{SO, kernel, arquitectura}"]
        E2["hallazgos_seguridad<br/>{usuarios anonimizados}"]
        E3["superficie_expuesta<br/>{puertos con servicios}"]
    end

    subgraph IA["🧠 FASE 2: GEMINI 2.5 FLASH"]
        F1["📝 Prompt enriquecido<br/>• Contexto del SO/kernel<br/>• Restricción anti-alucinación<br/>• Análisis de CVEs por kernel"]
        F2["🎯 Structured Outputs<br/>response_schema<br/>ReporteAuditoriaSchema"]
        F3["🌡️ Temperatura 0.2<br/>Consistencia determinística"]
        F4["🔄 Reintentos exponenciales<br/>Máx 4 | Delays: 4, 8, 16s"]
    end

    subgraph SCHEMA["📐 ESQUEMA PYDANTIC"]
        G1["score_seguridad: int<br/>justificacion_score: str<br/>resumen_ejecutivo: str"]
        G2["hallazgos_prioritarios: List[str]"]
        G3["tabla_riesgos: List[RiesgoFila]<br/>• id_riesgo<br/>• riesgo_detectado<br/>• nivel_impacto<br/>• descripcion"]
        G4["recomendaciones: List[RecomendacionTecnica]<br/>• titulo<br/>• comandos: List[str]<br/>• explicacion"]
    end

    subgraph RENDER["📄 FASE 3: GENERACIÓN DE REPORTE"]
        H1["⚙️ Parseo JSON → Markdown<br/>Estructura 100% controlada"]
        H2["🎨 Markdown → HTML<br/>• Tablas estilizadas<br/>• Bloques de código bash"]
        H3["📑 xhtml2pdf<br/>HTML → PDF"]
    end

    subgraph OUTPUT["💾 SALIDA DUAL"]
        I1["📄 Reporte_Auditoria_<br/>timestamp.pdf"]
        I2["📝 Reporte_Auditoria_<br/>timestamp.md"]
    end

    A1 --> A2 --> B1 --> B2
    B2 --> C1 --> C2 --> C3
    C3 --> D1 --> D2 --> D3
    D3 --> E1 --> E2 --> E3
    E3 --> F1 --> F2 --> F3 --> F4
    F4 --> G1 --> G2 --> G3 --> G4
    G4 --> H1 --> H2 --> H3
    H3 --> I1
    H3 --> I2

    style INPUT fill:#1e1e2f,stroke:#6c5ce7,stroke-width:2px,color:#fff
    style CONNECTION fill:#2f1e2f,stroke:#e84393,stroke-width:2px,color:#fff
    style EXTRACTION fill:#1e2f2f,stroke:#00b894,stroke-width:2px,color:#fff
    style PORTS fill:#2f2e1e,stroke:#fdcb6e,stroke-width:2px,color:#fff
    style DATA fill:#1e2f3f,stroke:#0984e3,stroke-width:2px,color:#fff
    style IA fill:#2f1e3f,stroke:#a29bfe,stroke-width:2px,color:#fff
    style SCHEMA fill:#2f2e3f,stroke:#dfe6e9,stroke-width:2px,color:#fff
    style RENDER fill:#1e3f2f,stroke:#55efc4,stroke-width:2px,color:#fff
    style OUTPUT fill:#3f2e1e,stroke:#ff7675,stroke-width:2px,color:#fff
```
---
## ✨ Características

### Core Features
- 🔐 **Conexión SSH segura** con verificación de huellas digitales (prevención MITM)
- 👤 **Anonimización automática** de usuarios (GDPR/LOPD compliant)
- 🔍 **Escaneo inteligente de puertos** con detección de servicios/procesos
- 🖥️ **Detección de sistema operativo** (distribución, versión, kernel, arquitectura)
- 🤖 **Análisis con IA** usando Google Gemini (Structured Outputs)
- 📊 **Score de seguridad** numérico (0-100) con justificación
- 📈 **Matriz de riesgos** con niveles de impacto (Crítico/Alto/Medio/Bajo)
- 🛠️ **Recomendaciones ejecutables** con comandos listos para copiar/pegar
- 📄 **Reportes profesionales** en PDF y Markdown
- 🔄 **Sistema de reintentos** con backoff exponencial para APIs

### Advanced Features
- 🎯 **Detección de servicios por puerto** usando múltiples estrategias:
  - `ss -lnp` con sudo (muestra proceso dueño)
  - `lsof -i` con sudo (alternativa)
  - `/etc/services` (diccionario estándar)
  - Tabla interna con +50 servicios conocidos
- 🧠 **Análisis contextual** que correlaciona:
  - Versiones de kernel con CVEs públicos
  - Servicios expuestos con cuentas de usuario
  - Puertos críticos con servicios de alto riesgo
- ⚡ **Detección de servicios prohibidos** (telnet, FTP, VNC, RDP, etc.)
---

---
## 📦 Requisitos Previos

- **Python 3.9 o superior**
- **Servidor Linux** objetivo (Ubuntu/Debian recomendado)
- **Acceso SSH** con llave privada (Ed25519 o RSA)
- **API Key de Google Gemini** (gratuita en [Google AI Studio](https://aistudio.google.com/))
- **Permisos de lectura** en el servidor para `/etc/passwd` y comandos de red
---

## Instalación

### 1. Clonar el repositorio
```bash
git clone https://github.com/p175624/Proyecto-IA-Auditor
cd Proyecto-IA-Auditor
```

### 2. Crear y activar el entorno virtual

Se recomienda usar un entorno virtual para aislar las dependencias del proyecto.

```bash
# Crear el entorno virtual
python3 -m venv venv

# Activar en macOS / Linux
source venv/bin/activate

# Activar en Windows (CMD)
venv\Scripts\activate.bat

# Activar en Windows (PowerShell)
venv\Scripts\Activate.ps1
```

Una vez activado, verás el prefijo `(venv)` en tu terminal:
```
(venv) usuario@equipo:~/pipeline-auditoria$
```

### 3. Instalar las dependencias
```bash
pip install -r requirements.txt
```

> Para desactivar el entorno virtual cuando termines: `deactivate`

---
## Configuración
Crea un archivo `.env` en la raíz del proyecto con las siguientes variables:
```env
# .env
GEMINI_API_KEY=tu_api_key_aqui
SSH_HOST=192.168.1.100
SSH_USER=tu_usuario
SSH_KEY_PATH=/home/user/.ssh/id_ed25519
SSH_KNOWN_HOSTS_PATH=/home/user/.ssh/known_hosts  # Opcional

# Opcional: Mejora la detección de servicios (permite ver procesos)
SUDO_PASSWORD=tu_contraseña_sudo
```
---
## Obtención de API Key de Gemini
Visita Google AI Studio

Inicia sesión con tu cuenta de Google

Haz clic en "Get API key"

Crea una nueva API key

Copia la clave en tu archivo .env
---

---
## Uso
```bash
python main.py
```

## Flujo de ejecución esperado
```bash
╔══════════════════════════════════════════════════════╗
║       🛡️  PIPELINE DE AUDITORÍA DE SEGURIDAD  🛡️       ║
║       Estándar: CIS — Con Salidas Estructuradas       ║
╚══════════════════════════════════════════════════════╝

  ✅  Variables de entorno verificadas correctamente.
  🔑  SUDO_PASSWORD detectado — detección de servicios con privilegios habilitada.

┌──────────────────────────────────────────────────────┐
│  📡  FASE 1 — Extracción de datos del servidor        │
└──────────────────────────────────────────────────────┘
  🔐  Conectando a 192.168.1.100 como 'admin'...
  ✅  Conexión SSH establecida exitosamente.
  🔍  Escaneando puertos en escucha...
  🔎  Identificando servicios en 12 puerto(s):
       TCP/22       → sshd
       TCP/80       → nginx
       TCP/443      → nginx
       TCP/3306     → mysqld
       TCP/5432     → postgres
       TCP/6379     → redis-server
       TCP/8080     → java
       TCP/8443     → apache2
       UDP/53       → systemd-resolve
       UDP/123      → chronyd
       UDP/161      → snmpd
       UDP/514      → rsyslogd
  📋  Puertos detectados: 12
  🖥️   Detectando sistema operativo y kernel...
  ✅  SO: Ubuntu 22.04.3 LTS | Kernel: 5.15.0-91-generic
  👤  Analizando cuentas de usuario (/etc/passwd)...
  👥  Usuarios relevantes encontrados: 8
  🔌  Conexión SSH cerrada.

┌──────────────────────────────────────────────────────┐
│  🤖  FASE 2 — Análisis Estructurado con IA           │
└──────────────────────────────────────────────────────┘
  ⏳  Enviando consulta a Gemini... (Intento 1/4)
  ✅  ¡Datos estructurados JSON devueltos por la IA correctamente!

┌──────────────────────────────────────────────────────┐
│  📄  FASE 3 — Generación del Reporte PDF              │
└──────────────────────────────────────────────────────┘
  ⚙️   Parseando JSON estructurado y construyendo HTML estable...
  📑  Reporte PDF Estabilizado → Reporte_Auditoria_20260112_143022.pdf
  📝  Reporte Markdown Guardado → Reporte_Auditoria_20260112_143022.md

╔══════════════════════════════════════════════════════╗
║          ✅  AUDITORÍA COMPLETADA CON ÉXITO           ║
╚══════════════════════════════════════════════════════╝
```

Al finalizar, encontrarás en el directorio de trabajo:
```
Reporte_Auditoria_YYYYMMDD_HHMMSS.pdf
Reporte_Auditoria_YYYYMMDD_HHMMSS.md
```
---
## Seguridad

✅ Verificación de host SSH (previene MITM attacks)

✅ Anonimización de datos antes del análisis externo

✅ Sin almacenamiento de credenciales en código

✅ Variables de entorno para datos sensibles

✅ Conexiones SSH con llaves (no contraseñas)

✅ Timeout configurable en conexiones

✅ Múltiples estrategias de detección con fallback

✅ Soporte opcional de sudo (no requiere permisos excesivos)

---
