from django.contrib.auth.models import User
from django.core.validators import (
    MinValueValidator,
    MaxValueValidator,
    MinLengthValidator,
)
from django.db import models
from django.db.models import CheckConstraint, Q


class Vulnerability(models.Model):

    SEVERITY_CHOICES = (
        ("B", "Baixo"),
        ("M", "Médio"),
        ("A", "Alto"),
        ("C", "Crítico"),
    )

    title = models.CharField(max_length=255)
    severity = models.CharField(max_length=1, choices=SEVERITY_CHOICES)
    cvss = models.FloatField(
        validators=[MinValueValidator(0.0), MaxValueValidator(10.0)],
    )
    publication_date = models.DateField()
    asset_hostname = models.CharField(max_length=20)
    asset_ip_address = models.CharField(
        max_length=15, validators=[MinLengthValidator(7)]
    )

    is_fixed = models.BooleanField(default=False)
    author = models.ForeignKey(User, on_delete=models.PROTECT)

    class Meta:
        constraints = (
            CheckConstraint(
                check=Q(cvss__gte=0.0) & Q(cvss__lte=10.0),
                name="vulnerability_cvss_range",
            ),
        )

    def __str__(self):
        return self.title


class AuditLog(models.Model):
    vulnerability = models.ForeignKey(Vulnerability, on_delete=models.PROTECT)
    updated_at = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField()
    updated_by = models.ForeignKey(User, on_delete=models.PROTECT)

    def __str__(self):
        return self.vulnerability
