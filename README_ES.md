# 🔍 Analizador de Logs Linux basado en SSH con Chat

Un analizador de logs inteligente para sistemas Linux con acceso SSH que recopila automáticamente información del sistema, analiza logs y proporciona un chat interactivo con soporte de IA.

## 🚀 Características

- **🔍 Análisis Automático del Sistema**: Recopila información completa del sistema
- **📊 Análisis de Logs**: Analiza logs del sistema con soporte de IA
- **🤖 Chat de IA**: Chat interactivo con Ollama para preguntas del sistema
- **🐳 Análisis de Docker**: Análisis detallado de contenedores Docker
- **☸️ Soporte de Kubernetes**: Análisis de clústeres Kubernetes
- **🖥️ Integración Proxmox**: Monitoreo de clústeres Proxmox
- **📧 Análisis de Servidores de Correo**: Mailcow, Postfix y otros servidores de correo
- **🔐 Análisis de Seguridad**: Seguridad de red y verificaciones CVE
- **📄 Reportes Automáticos**: Reportes del sistema con `--auto-report` o `--report-and-chat`
- **🔍 Análisis de Seguridad CVE**: Bases de datos CVE reales (NIST NVD, DBs Europeas) + análisis de IA
- **🇪🇺 Cumplimiento UE**: Bases de datos CVE europeas para GDPR y directiva NIS
- **🌐 Reportes HTML5**: Reportes HTML5 interactivos con elementos clickeables y pestañas

## 📦 Instalación

### Prerrequisitos

- Python 3.8+
- Acceso SSH al sistema objetivo
- Ollama (para funciones de IA)

### Instalación

```bash
# Clonar repositorio
git clone <repository-url>
cd macos-loganalyser

# Instalar dependencias
pip install -r requirements.txt

# Instalar Ollama (si no está disponible)
curl -fsSL https://ollama.ai/install.sh | sh
```

## 🎯 Uso

### Uso Básico

```bash
# Análisis simple
python3 ssh_chat_system.py user@hostname

# Con contraseña
python3 ssh_chat_system.py user@hostname --password mipassword

# Con clave SSH
python3 ssh_chat_system.py user@hostname --key-file ~/.ssh/id_rsa
```

### Análisis de Seguridad CVE

```bash
# Análisis CVE con enfoque híbrido (NVD + Ollama) - Recomendado
python3 ssh_chat_system.py user@hostname --with-cve --cve-database hybrid

# Solo base de datos NIST NVD
python3 ssh_chat_system.py user@hostname --with-cve --cve-database nvd

# Solo análisis de IA Ollama
python3 ssh_chat_system.py user@hostname --with-cve --cve-database ollama

# Bases de datos CVE europeas (BSI, NCSC, ENISA, CERT-EU)
python3 ssh_chat_system.py user@hostname --with-cve --cve-database european

# Híbrido con bases de datos europeas
python3 ssh_chat_system.py user@hostname --with-cve --cve-database hybrid-european

# Modo de cumplimiento UE (GDPR, directiva NIS)
python3 ssh_chat_system.py user@hostname --with-cve --cve-database european --eu-compliance

# Con caché para mejor rendimiento
python3 ssh_chat_system.py user@hostname --with-cve --cve-cache

# Modo offline (solo datos locales)
python3 ssh_chat_system.py user@hostname --with-cve --cve-offline
```

### Reportes Automáticos

```bash
# Generar solo reporte y salir
python3 ssh_chat_system.py user@hostname --auto-report

# Generar reporte y luego iniciar chat
python3 ssh_chat_system.py user@hostname --report-and-chat

# Reporte con análisis CVE
python3 ssh_chat_system.py user@hostname --auto-report --with-cve --cve-database hybrid

# Reporte con análisis CVE europeo
python3 ssh_chat_system.py user@hostname --auto-report --with-cve --cve-database european --eu-compliance

# Reporte HTML5 con elementos clickeables
python3 ssh_chat_system.py user@hostname --auto-report --html-report

# Reporte HTML5 con análisis CVE
python3 ssh_chat_system.py user@hostname --auto-report --with-cve --html-report
```

### Opciones Avanzadas

```bash
# Análisis rápido
python3 ssh_chat_system.py user@hostname --quick

# Sin recopilación de logs
python3 ssh_chat_system.py user@hostname --no-logs

# Incluir análisis de seguridad de red
python3 ssh_chat_system.py user@hostname --include-network-security

# Modo debug
python3 ssh_chat_system.py user@hostname --debug
```

## 🎯 Funciones de Chat

Después del análisis, puede hacer preguntas:

### Preguntas del Sistema
- `s1` - ¿Qué servicios están ejecutándose?
- `s2` - Estado del espacio en disco?
- `s3` - Problemas de seguridad?
- `s4` - Procesos principales?
- `s5` - Rendimiento del sistema?

### Preguntas de Docker
- `d1` - Estado de Docker y contenedores?
- `d2` - Problemas de Docker?
- `d3` - Contenedores ejecutándose?
- `d4` - Imágenes de Docker?

### Preguntas de Kubernetes
- `k1` - Estado del clúster?
- `k2` - Problemas de Kubernetes?
- `k3` - Pods ejecutándose?

### Preguntas de Proxmox
- `p1` - Estado de Proxmox?
- `p2` - Problemas de Proxmox?
- `p3` - VMs ejecutándose?

### Seguridad de Red
- `n1` - Análisis completo de seguridad de red
- `n2` - Servicios accesibles externamente
- `n3` - Escaneo de puertos
- `n4` - Pruebas de servicios

## 📁 Salida

### Reportes del Sistema
- **Ubicación**: `system_reports/`
- **Formato**: Markdown
- **Contenido**: Análisis completo del sistema con recomendaciones

### Archivos de Log
- **Formato**: `.tar.gz`
- **Contenido**: Logs recopilados e información del sistema

### Caché CVE
- **Ubicación**: `cve_cache.json`
- **Validez**: 24 horas
- **Contenido**: Datos CVE en caché para mejor rendimiento

### Caché CVE Europeo
- **Ubicación**: `european_cve_cache.json`
- **Validez**: 24 horas
- **Contenido**: Datos CVE europeos en caché

### Reportes HTML5
- **Ubicación**: `system_reports/` (archivos `.html`)
- **Características**: 
  - 📋 Pestañas interactivas (Resumen, Detalles, Seguridad, Rendimiento)
  - 🔽 Secciones desplegables para información detallada
  - 📊 Tarjetas de estado con efectos hover
  - 📈 Barras de progreso para métricas de rendimiento
  - 🎨 Interfaz de usuario moderna y responsiva
  - 🌐 Apertura automática en navegador
  - 📱 Optimizado para móviles

## 🔧 Configuración

### Clave API NVD (Opcional)
Para límites de tasa más altos, puede usar una clave API NVD:

```bash
export NVD_API_KEY="tu-clave-api-aqui"
```

### Modelos Ollama
El sistema selecciona automáticamente el mejor modelo disponible:
- **Análisis complejos**: `llama3.2:70b` o `llama3.1:70b`
- **Chat estándar**: `llama3.2:8b` o `llama3.1:8b`

## 🐛 Solución de Problemas

### Problemas de Conexión SSH
```bash
# Probar conexión SSH
ssh user@hostname

# Verificar permisos de clave SSH
chmod 600 ~/.ssh/id_rsa
```

### Problemas de Ollama
```bash
# Iniciar Ollama
ollama serve

# Verificar modelos disponibles
ollama list
```

### Problemas de Análisis CVE
```bash
# Probar API NVD
curl "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=openssh"

# Eliminar caché CVE
rm cve_cache.json
rm european_cve_cache.json
```

## 📈 Consejos de Rendimiento

1. **Modo Rápido**: Use `--quick` para análisis rápidos
2. **Caché**: Habilite `--cve-cache` para análisis repetidos
3. **Modo Offline**: Use `--cve-offline` para datos locales
4. **Clave API NVD**: Para límites de tasa más altos
5. **DBs Europeas**: Para cumplimiento específico de la UE

## 🤝 Contribuir

1. Hacer fork del repositorio
2. Crear una rama de características
3. Hacer commit de sus cambios
4. Hacer push a la rama
5. Crear un pull request

## 📄 Licencia

Este proyecto está licenciado bajo la Licencia MIT.

## 🔗 Enlaces

- [NIST NVD](https://nvd.nist.gov/) - Base de Datos Nacional de Vulnerabilidades
- [BSI](https://www.bsi.bund.de/) - Oficina Federal de Seguridad de la Información
- [NCSC](https://www.ncsc.gov.uk/) - Centro Nacional de Ciberseguridad
- [ENISA](https://www.enisa.europa.eu/) - Agencia de la Unión Europea para la Ciberseguridad
- [CERT-EU](https://cert.europa.eu/) - Equipo de Respuesta a Emergencias Informáticas para Instituciones de la UE
- [Ollama](https://ollama.ai/) - Motor LLM Local
- [MITRE CVE](https://cve.mitre.org/) - Vulnerabilidades y Exposiciones Comunes 