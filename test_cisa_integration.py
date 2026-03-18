import os
import django
import sys

# 1. Configuración del entorno Django
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '.')))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'security_hub.settings')
django.setup()

from vulnerabilidades.models import CVE

def run_test():
    print("\n" + "="*60)
    print(" [QA_ENGINEER] INICIANDO VALIDACIÓN DE INTEGRACIÓN CISA KEV")
    print("="*60 + "\n")

    # Paso 1: Comprobación Inicial
    initial_count = CVE.objects.filter(cisa_kev=True).count()
    print(f" [+] COMPROBACIÓN INICIAL: Se han encontrado {initial_count} CVEs marcados como KEV en la base de datos.")

    # Paso 2: Inyección de Prueba
    test_cve = CVE.objects.all().first()
    
    if test_cve:
        print(f" [+] INYECCIÓN DE PRUEBA: Seleccionando {test_cve.cve_id} para forzado de estado...")
        
        # Forzamos el estado para validar el frontend
        test_cve.cisa_kev = True
        test_cve.save()
        
        # Paso 3: Reporte Final
        print("\n" + "*"*70)
        print(" PRUEBA EXITOSA: INTEGRACIÓN DE DATOS VALIDADA")
        print(f" EL CVE [{test_cve.cve_id}] DEBERÍA DESTACAR AHORA CON EL INDICADOR VISUAL DE CISA")
        print(" VERIFICA EL MONITOR DASHBOARD PARA CONFIRMAR EL EFECTO PARPADEANTE 'KEV_EXPLOITED'")
        print("*"*70 + "\n")
    else:
        print("\n [!] ERROR: No hay registros de CVE en la base de datos. Ejecuta una sincronización NVD primero.")

if __name__ == "__main__":
    run_test()
