import os
from celery import Celery

# Establecer las configuraciones predeterminadas de Django para Celery
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'security_hub.settings')

app = Celery('security_hub')

# Usar una cadena aquí para que el trabajador no tenga que serializar
# el objeto de configuración a procesos secundarios.
app.config_from_object('django.conf:settings', namespace='CELERY')

# Cargar archivos tasks.py de todas las aplicaciones registradas.
app.autodiscover_tasks()

@app.task(bind=True)
def debug_task(self):
    print(f'Request: {self.request!r}')
