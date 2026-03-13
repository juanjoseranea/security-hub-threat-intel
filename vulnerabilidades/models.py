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
    analyst_notes = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"{self.cve_id} ({self.severity})"
