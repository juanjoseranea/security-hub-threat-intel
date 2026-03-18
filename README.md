# 🛡️ Security Hub - Terminal SOC L1 (v2.5.0)

**Security Hub** es una estación de triaje y monitorización de vulnerabilidades de grado profesional, diseñada para analistas de SOC L1. La herramienta automatiza la ingesta de amenazas globales, enriquece los datos con inteligencia externa y proporciona métricas de rendimiento en tiempo real para optimizar la respuesta ante incidentes.

---

## 🚀 Funcionalidades Principales

### 1. Automatización e Inteligencia de Amenazas (Threat Intel)
*   **Ingesta Autónoma NVD**: Sincronización automática con la API de NIST (National Vulnerability Database) mediante tareas en segundo plano.
*   **Enriquecimiento CISA KEV**: Identificación proactiva de vulnerabilidades que están siendo explotadas activamente en el mundo real (Known Exploited Vulnerabilities).
*   **Planificador Celery Beat**: Actualización automática del catálogo cada 12 horas sin intervención humana.
*   **Auditoría de Bots**: Registro físico de ejecución (`auditoria_bots.log`) para monitorizar el ciclo de vida de los procesos autónomos.

### 2. Monitor de Triage Avanzado
*   **Flujo en Tiempo Real**: Visualización dinámica de los últimos CVEs detectados con puntuaciones CVSS y niveles de severidad.
*   **SLA Dinámico**: Temporizadores visuales incorporados que alertan (parpadeo rojo) si una vulnerabilidad crítica supera los 15 minutos sin atención.
*   **Gestión de Estados**: Flujo de trabajo completo: `PENDIENTE`, `INVESTIGANDO`, `FALSO POSITIVO` y `RESUELTO`.
*   **Registro de Auditoría**: Cada CVE permite añadir notas técnicas para mantener la trazabilidad de la investigación.

### 3. Métricas SOC L1 y Analíticas
*   **Panel de Rendimiento**: Gráficos interactuando con **Chart.js** que muestran visualmente el rendimiento del equipo.
*   **MTTA (Mean Time to Acknowledge)**: Tiempo medio de reconocimiento del incidente.
*   **MTTR (Mean Time to Resolve)**: Tiempo medio de resolución de la amenaza.
*   **Reporte de Turno**: Generación instantánea de resúmenes de las últimas 8 horas para cambios de turno, incluyendo métricas y notas de analistas.

### 4. Enriquecimiento OSINT y Playbooks
*   **Enlaces Externos**: Acceso directo a bases de datos de NIST, repositorios de exploits en GitHub y archivos de Exploit-DB para cada CVE.
*   **Playbooks de Mitigación**: Generación automática de pasos técnicos de mitigación basados en la tecnología detectada en la descripción de la vulnerabilidad.

### 5. Exportación y Auditoría
*   **Vuelcos CSV**: Herramienta de exportación con filtrado temporal (7, 14, 30 días o histórico completo).
*   **Estado del Núcleo**: Interfaz dedicada para monitorizar la salud de los trabajadores de Celery y los resultados de las tareas asíncronas.

---

## 🎨 Interfaz y Estética
*   **Estética Hacker/Ciberpunk**: Diseño basado en terminales de alta seguridad con fuentes monoespaciadas (`Fira Code`).
*   **Sistema de Temas Dinámico**:
    *   **Modo Oscuro**: Para entornos de alta concentración.
    *   **Modo Claro**: Para presentaciones y visibilidad en entornos iluminados.
    *   **Modo Gris**: Calibrado industrial para descanso visual.
*   **Localización Completa**: Interfaz 100% traducida al español comercial y técnico.

---

## 🛠️ Stack Tecnológico
*   **Lenguaje**: Python 3.x
*   **Framework Web**: Django 5.x
*   **Gestión de Tareas**: Celery + Redis / Celery Beat
*   **Base de Datos**: SQLite (Prototipado) / Soporte para PostgreSQL
*   **Frontend**: HTML5, Vanilla CSS3 (Custom Properties), JavaScript (AJAX/Fetch API)
*   **Librerías de Visualización**: Chart.js
*   **Tipografía**: Google Fonts (Inter & Fira Code)

---

## ⚙️ Configuración del Analista
Para ejecutar el entorno SOC localmente:
1. Activar el entorno virtual: `.\venv\Scripts\activate`
2. Iniciar servidor Django: `python manage.py runserver`
3. Iniciar Trabajador Celery: `celery -A security_hub worker --loglevel=info`
4. Iniciar Celery Beat: `celery -A security_hub beat --loglevel=info`

---
**[SISTEMA DE ACCESO RESTRINGIDO - SOC L1 OPERATIONS]**  
*Desarrollado para la gestión crítica de infraestructuras cibernéticas.*
