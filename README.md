# Security Hub - Threat Intelligence SOC Dashboard 🛡️

**Security Hub** es una plataforma de inteligencia de amenazas (Threat Intelligence) diseñada para analistas SOC L1. Permite monitorizar, gestionar y exportar vulnerabilidades reales (CVEs) en tiempo real consumiendo la API de NVD (National Vulnerability Database).

Desarrollado por [Juan Jose Ranea](https://www.linkedin.com/in/juanjoseranea/).

## ✨ Características Principales

- **🔄 Sincronización en Tiempo Real**: Conexión directa con la API de NVD para obtener los últimos CVEs relacionados con Python.
- **🚥 Semáforo de Gravedad**: Clasificación visual automática (Crítica, Alta, Media, Baja) basada en puntuaciones CVSS.
- **📋 Workflow de Incidentes**: Gestión del ciclo de vida de vulnerabilidades (Pendiente, Investigando, Resuelto).
- **🎨 Temas Personalizables**: Modos Oscuro, Claro y Escala de Grises con persistencia en el navegador.
- **📥 Centro de Reportes**: Exportación a CSV filtrada por 7, 14, 30 días o histórico completo.
- **⚙️ Tareas Asíncronas**: Motor de Celery + Redis/SQLite para procesamiento en segundo plano sin bloquear la UI.

## 🚀 Instalación y Uso

### 1. Clonar y Preparar Entorno
```bash
git clone https://github.com/TU_USUARIO/security-hub.git
cd security-hub
python -m venv venv
source venv/bin/activate  # En Windows: .\venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Migraciones y Base de Datos
```bash
python manage.py makemigrations
python manage.py migrate
```

### 3. Iniciar Servicios
Necesitarás dos terminales abiertas:
- **Terminal 1 (Django)**: `python manage.py runserver`
- **Terminal 2 (Celery)**: `celery -A security_hub worker --loglevel=info -P solo`

Accede a `http://127.0.0.1:8000/`.

## 🛠️ Tecnologías

- **Backend**: Python, Django, Celery
- **Frontend**: HTML5, Vanilla CSS, JS (Tema dinámico)
- **Datos**: API NVD v2.0
- **Base de Datos/Broker**: SQLite (ideal para desarrollo local)

## 👤 Autor
**Juan Jose Ranea** - [@juanjoseranea](https://www.linkedin.com/in/juanjoseranea/)
