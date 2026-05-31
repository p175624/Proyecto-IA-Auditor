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
