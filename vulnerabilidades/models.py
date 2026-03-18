from django.db import models

class CVE(models.Model):
    STATUS_CHOICES = [
        ('PENDING', 'Pendiente'),
        ('INVESTIGATING', 'Investigando'),
        ('FALSE_POSITIVE', 'Falso Positivo'),
        ('RESOLVED', 'Resuelto'),
    ]

    SEVERITY_CHOICES = [
        ('CRITICAL', 'Crítica'),
        ('HIGH', 'Alta'),
        ('MEDIUM', 'Media'),
        ('LOW', 'Baja'),
        ('UNKNOWN', 'Desconocida'),
    ]

    cve_id = models.CharField(max_length=20, unique=True)
    description = models.TextField()
    published_date = models.CharField(max_length=50)
    
    # Nuevos campos para SOC L1
    cvss_score = models.FloatField(default=0.0)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default='UNKNOWN')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PENDING')
    is_false_positive = models.BooleanField(default=False)
    analyst_notes = models.TextField(blank=True, null=True)
    
    # Métricas de Auditoría
    created_at = models.DateTimeField(auto_now_add=True)
    investigated_at = models.DateTimeField(null=True, blank=True)
    resolved_at = models.DateTimeField(null=True, blank=True)

    # Fase 2: Inteligencia CISA KEV
    cisa_kev = models.BooleanField(default=False)
    cisa_date_added = models.DateField(null=True, blank=True)

    def __str__(self):
        return f"{self.cve_id} ({self.severity}) {'[KEV]' if self.cisa_kev else ''}"

class IncidentNote(models.Model):
    cve = models.ForeignKey(CVE, on_delete=models.CASCADE, related_name='incident_notes')
    note = models.TextField()
    author = models.CharField(max_length=100, default='Analista L1')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Nota para {self.cve.cve_id} por {self.author} (@{self.created_at})"
