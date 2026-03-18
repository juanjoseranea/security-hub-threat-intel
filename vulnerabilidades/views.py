import csv
from datetime import datetime, timedelta
from django.http import HttpResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.db.models import Count
import re
from .models import CVE, IncidentNote
from .tasks import fetch_nvd_python_cves, sync_cisa_kev_catalog
from django_celery_results.models import TaskResult
from django.http import JsonResponse
from django.views.decorators.http import require_POST

def home(request):
    """Página de inicio (Launchpad) con Métricas en Español"""
    severity_counts = CVE.objects.values('severity').annotate(total=Count('severity'))
    status_counts = CVE.objects.values('status').annotate(total=Count('status'))
    total_cves = CVE.objects.count()
    
    stats = {
        'total': total_cves,
        'severity': {item['severity']: item['total'] for item in severity_counts},
        'status': {item['status']: item['total'] for item in status_counts}
    }
    
    return render(request, 'vulnerabilidades/home.html', {'stats': stats})

def dashboard(request):
    """Monitor de Vulnerabilidades en Español con Métricas SOC"""
    from django.db.models import Avg, F
    from django.utils import timezone
    
    query = request.GET.get('q')
    cves = CVE.objects.filter(is_false_positive=False)
    
    if query:
        cves = cves.filter(cve_id__icontains=query) | cves.filter(description__icontains=query)
    
    # Cálculo de Métricas MTTA (Reconocimiento) y MTTR (Resolución)
    # MTTA: Promedio de (investigated_at - created_at)
    # MTTR: Promedio de (resolved_at - created_at)
    
    mtta_query = CVE.objects.filter(investigated_at__isnull=False).annotate(
        diff=F('investigated_at') - F('created_at')
    ).aggregate(Avg('diff'))
    
    mttr_query = CVE.objects.filter(resolved_at__isnull=False).annotate(
        diff=F('resolved_at') - F('created_at')
    ).aggregate(Avg('diff'))
    
    def duration_to_mins(duration):
        if duration:
            return round(duration.total_seconds() / 60, 2)
        return 0
        
    mtta_avg = duration_to_mins(mtta_query['diff__avg'])
    mttr_avg = duration_to_mins(mttr_query['diff__avg'])
    
    cves_list = cves.order_by('-cvss_score', '-id')[:50]
    
    context = {
        'cves': cves_list,
        'query': query,
        'metrics': {
            'mtta': mtta_avg,
            'mttr': mttr_avg
        }
    }
    return render(request, 'vulnerabilidades/dashboard.html', context)

def update_status(request, pk):
    """Actualizar estado del incidente y registrar marcas de tiempo"""
    from django.utils import timezone
    if request.method == 'POST':
        cve = get_object_or_404(CVE, pk=pk)
        new_status = request.POST.get('status')
        if new_status in dict(CVE.STATUS_CHOICES):
            # Lógica de marcas de tiempo para métricas
            if new_status == 'INVESTIGATING' and not cve.investigated_at:
                cve.investigated_at = timezone.now()
            elif new_status == 'RESOLVED' and not cve.resolved_at:
                cve.resolved_at = timezone.now()
                
            cve.status = new_status
            cve.save()
            messages.success(request, f"Estado de {cve.cve_id} actualizado correctamente.")
    return redirect('dashboard')

@require_POST
def mark_false_positive(request, pk):
    """Marcar vulnerabilidad como falso positivo vía AJAX"""
    cve = get_object_or_404(CVE, pk=pk)
    cve.is_false_positive = True
    cve.status = 'FALSE_POSITIVE'
    cve.save()
    return JsonResponse({'status': 'success', 'cve_id': cve.cve_id})

def shift_report(request):
    """Generar reporte de turno de las últimas 8 horas"""
    from django.utils import timezone
    ocho_horas_atras = timezone.now() - timedelta(hours=8)
    hoy = timezone.now().date()
    
    resueltas_hoy = CVE.objects.filter(status='RESOLVED', resolved_at__date=hoy).count()
    pendientes = CVE.objects.filter(status='PENDING').count()
    notas_recientes = IncidentNote.objects.filter(created_at__gte=ocho_horas_atras).order_by('-created_at')
    
    data = {
        'resumen': f"Reporte de Turno :: {timezone.now().strftime('%Y-%m-%d %H:%M')}",
        'metricas': {
            'resueltas_hoy': resueltas_hoy,
            'pendientes_criticas': pendientes
        },
        'analisis': [f"[{n.created_at.strftime('%H:%I')}] {n.cve.cve_id}: {n.note}" for n in notas_recientes]
    }
    
    report_text = f"REPORTE DE TURNO SOC L1\n"
    report_text += f"----------------------\n"
    report_text += f"- Resueltas hoy: {resueltas_hoy}\n"
    report_text += f"- Pendientes totales: {pendientes}\n\n"
    report_text += f"Últimas notas de analistas (8h):\n"
    for item in data['analisis']:
        report_text += f"- {item}\n"
    
    return JsonResponse({'report': report_text})

def export_csv(request):
    """Exportar reportes a CSV con filtros temporales"""
    days = request.GET.get('days', 'all')
    cves = CVE.objects.all().order_by('-published_date')

    if days != 'all':
        try:
            days_int = int(days)
            # Nota: Filtrado simplificado basado en fecha actual ya que published_date es string en este sprint.
            # En un entorno real se usaría DateTimeField para filtrado preciso.
            limit_date = datetime.now() - timedelta(days=days_int)
            # Para este prototipo, filtramos los últimos N registros como aproximación si la fecha no es parseable fácilmente
            cves = cves[:days_int * 2] # Aproximación para el demo
        except ValueError:
            pass

    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="reporte_amenazas_{days}dias.csv"'

    writer = csv.writer(response)
    writer.writerow(['CVE ID', 'Severidad', 'Score CVSS', 'Estado', 'Fecha Publicación', 'Descripción'])

    for cve in cves:
        writer.writerow([cve.cve_id, cve.get_severity_display(), cve.cvss_score, cve.get_status_display(), cve.published_date, cve.description])

    return response

def sync_now(request):
    fetch_nvd_python_cves.delay()
    messages.success(request, "Sincronización NVD iniciada en segundo plano.")
    return redirect('home')

def sync_cisa(request):
    from .tasks import sync_cisa_kev_catalog
    sync_cisa_kev_catalog.delay()
    messages.success(request, "Sincronización CISA KEV iniciada en segundo plano.")
    return redirect('home')

def system_status(request):
    tasks = TaskResult.objects.all().order_by('-date_done')[:10]
    return render(request, 'vulnerabilidades/status.html', {'tasks': tasks})

@require_POST
def trigger_manual_sync(request):
    """Lanza sincronización total (NVD + CISA) en segundo plano"""
    fetch_nvd_python_cves.delay()
    sync_cisa_kev_catalog.delay()
    return JsonResponse({'status': 'success', 'message': 'Sincronización iniciada correctamente.'})

@require_POST
def add_note(request, pk):
    """Añade una nota de auditoría a una vulnerabilidad"""
    cve = get_object_or_404(CVE, pk=pk)
    note_text = request.POST.get('note')
    if note_text:
        IncidentNote.objects.create(cve=cve, note=note_text)
        messages.success(request, "Nota de auditoría registrada.")
    return redirect('dashboard')

def get_playbook(request, pk):
    """Genera un playbook de mitigación dinámico"""
    cve = get_object_or_404(CVE, pk=pk)
    desc = cve.description.lower()
    
    # Lógica simple de extracción de tecnología
    tech = "Tecnología Desconocida"
    if 'python' in desc: tech = "Entorno Python"
    elif 'javascript' in desc or 'node' in desc: tech = "Entorno Node.js/JS"
    elif 'sql' in desc: tech = "Base de Datos SQL"
    elif 'linux' in desc or 'kernel' in desc: tech = "Sistema Linux"
    elif 'windows' in desc: tech = "Sistema Windows"
    
    playbook = {
        'tech': tech.upper(),
        'steps': [
            f"1. Aislar los activos que utilicen {tech}.",
            "2. Verificar existencia de parches oficiales del fabricante.",
            "3. Implementar reglas de detección en IDS/IPS y monitorizar logs de acceso."
        ]
    }
    return JsonResponse(playbook)
