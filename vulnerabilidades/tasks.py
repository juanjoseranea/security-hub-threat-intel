import requests
import logging
from celery import shared_task
from .models import CVE

logger = logging.getLogger(__name__)

def get_severity_from_score(score):
    if score >= 9.0:
        return 'CRITICAL'
    elif score >= 7.0:
        return 'HIGH'
    elif score >= 4.0:
        return 'MEDIUM'
    elif score > 0:
        return 'LOW'
    return 'UNKNOWN'

@shared_task
def fetch_nvd_python_cves():
    """
    Obtiene vulnerabilidades relacionadas con 'python' desde la API de NVD (NIST)
    incluyendo puntuaciones CVSS y severidad.
    """
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=python&resultsPerPage=20"
    try:
        response = requests.get(url, timeout=20, headers={'User-Agent': 'Mozilla/5.0'})
        response.raise_for_status()
        
        data = response.json()
        vulnerabilities = data.get('vulnerabilities', [])
        
        count = 0
        for item in vulnerabilities:
            cve_data = item.get('cve', {})
            cve_id = cve_data.get('id')
            
            # Descripción
            descriptions = cve_data.get('descriptions', [])
            description_text = "No hay descripción disponible"
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    description_text = desc.get('value')
                    break
            
            # CVSS Score y Severidad
            cvss_score = 0.0
            metrics = cve_data.get('metrics', {})
            
            # Intentamos obtener CVSS V3.1, luego V3.0, luego V2
            cvss_v31 = metrics.get('cvssMetricV31', [])
            cvss_v30 = metrics.get('cvssMetricV30', [])
            cvss_v2 = metrics.get('cvssMetricV2', [])
            
            if cvss_v31:
                cvss_score = cvss_v31[0].get('cvssData', {}).get('baseScore', 0.0)
            elif cvss_v30:
                cvss_score = cvss_v30[0].get('cvssData', {}).get('baseScore', 0.0)
            elif cvss_v2:
                cvss_score = cvss_v2[0].get('cvssData', {}).get('baseScore', 0.0)
            
            severity = get_severity_from_score(cvss_score)
            published_date = cve_data.get('published', 'N/A')
            
            # Guardamos o actualizamos
            CVE.objects.update_or_create(
                cve_id=cve_id,
                defaults={
                    'description': description_text,
                    'published_date': published_date,
                    'cvss_score': cvss_score,
                    'severity': severity
                }
            )
            count += 1
        
        return f"Éxito: Se procesaron {count} CVEs con datos de severidad enriquecidos."

    except Exception as e:
        logger.error(f"Error al conectar con la API de NVD: {e}")
        return f"Error: {str(e)}"
