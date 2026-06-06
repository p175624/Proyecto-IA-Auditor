# 🔐 Pipeline de Auditoría de Seguridad con IA
Script automatizado que realiza auditorías de seguridad en servidores Linux mediante SSH, analiza los hallazgos con Gemini 3.5 Flash y genera un reporte profesional en PDF.
```mermaid
flowchart TB
    A["🖥️ COMPUTADORA LOCAL<br/><b>Python Script</b>"]
    B["📡 CAPA DE FUENTE<br/><b>Servidor Linux</b><br/>/etc/passwd | Puertos"]
    C["🔐 CAPA DE INGESTA<br/><b>SSH (Paramiko)</b><br/>Conexión segura"]
    D["⚙️ CAPA DE PROCESAMIENTO<br/><b>Parsing + Anonimización</b><br/>Eliminación de PII"]
    E["💾 CAPA DE DATOS<br/><b>JSON Seguro</b><br/>Cifrado + Validación"]
    F["🧠 CAPA DE INTELIGENCIA<br/><b>Gemini IA</b><br/>Análisis y resúmenes"]
    G["📄 CAPA DE PRESENTACIÓN<br/><b>Markdown → PDF</b><br/>Informe ejecutivo"]
    A --> B --> C --> D --> E --> F --> G
    style A fill:#1e1e2f,stroke:#6c5ce7,stroke-width:2px,color:#fff
    style B fill:#1e2f2f,stroke:#00b894,stroke-width:2px,color:#fff
    style C fill:#2f1e2f,stroke:#e84393,stroke-width:2px,color:#fff
    style D fill:#2f2e1e,stroke:#fdcb6e,stroke-width:2px,color:#fff
    style E fill:#1e2f3f,stroke:#0984e3,stroke-width:2px,color:#fff
    style F fill:#2f1e3f,stroke:#a29bfe,stroke-width:2px,color:#fff
    style G fill:#2f2e3f,stroke:#dfe6e9,stroke-width:2px,color:#fff
```
---
## Requisitos previos
- Python 3.10 o superior
- Acceso SSH al servidor objetivo con una llave **Ed25519**
- El host del servidor debe estar registrado en tu archivo `known_hosts`
- API Key de [Google Gemini](https://aistudio.google.com/apikey)
---
## Instalación

### 1. Clonar el repositorio
```bash
git clone https://github.com/p175624/Proyecto_IA
cd Proyecto_IA
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
GEMINI_API_KEY=tu_api_key_de_gemini
SSH_HOST=192.168.1.100
SSH_USER=tu_usuario
SSH_KEY_PATH=/ruta/a/tu/llave_ed25519
# Opcional: ruta personalizada al known_hosts (por defecto usa ~/.ssh/known_hosts)
# SSH_KNOWN_HOSTS_PATH=/ruta/personalizada/known_hosts
```
### Registrar el servidor en known_hosts
Si aún no has conectado al servidor manualmente, registra su huella primero:
```bash
ssh-keyscan -H 192.168.1.100 >> ~/.ssh/known_hosts
```
---
## Uso
```bash
python main.py
```
Al finalizar, encontrarás en el directorio de trabajo:
```
Reporte_Auditoria_YYYYMMDD_HHMMSS.pdf
Reporte_Auditoria_YYYYMMDD_HHMMSS.md
```
---
## Seguridad
- Las IPs y nombres de usuario **nunca se envían a la API**. Antes del análisis son reemplazados por su hash SHA-256.
- La conexión SSH usa `RejectPolicy`, lo que significa que el script **rechaza hosts desconocidos** en lugar de aceptarlos automáticamente.
- Se requiere autenticación con llave privada Ed25519; no se admiten contraseñas.
---
## Estructura del proyecto
```
.
├── main.py            # Script principal
├── requirements.txt   # Dependencias
├── .env.example       # Ejemplo de Variables de entorno (.env)
└── .gitignore
```
---"# Auditor-IA" 
