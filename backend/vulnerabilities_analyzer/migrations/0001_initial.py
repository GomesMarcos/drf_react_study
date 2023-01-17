# Generated by Django 4.1.5 on 2023-01-17 15:06

from django.conf import settings
import django.core.validators
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="Vulnerability",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("title", models.CharField(max_length=255)),
                (
                    "severity",
                    models.CharField(
                        choices=[
                            ("B", "Baixo"),
                            ("M", "Médio"),
                            ("A", "Alto"),
                            ("C", "Crítico"),
                        ],
                        max_length=1,
                    ),
                ),
                (
                    "cvss",
                    models.FloatField(
                        validators=[
                            django.core.validators.MinValueValidator(0.0),
                            django.core.validators.MaxValueValidator(10.0),
                        ]
                    ),
                ),
                ("publication_date", models.DateField()),
                ("asset_hostname", models.CharField(max_length=20)),
                (
                    "asset_ip_address",
                    models.CharField(
                        max_length=15,
                        validators=[django.core.validators.MinLengthValidator(7)],
                    ),
                ),
                ("is_fixed", models.BooleanField(default=False)),
                (
                    "author",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name="AuditLog",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("created_at", models.DateTimeField()),
                (
                    "updated_by",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "vulnerability",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        to="vulnerabilities_analyzer.vulnerability",
                    ),
                ),
            ],
        ),
        migrations.AddConstraint(
            model_name="vulnerability",
            constraint=models.CheckConstraint(
                check=models.Q(("cvss__gte", 0.0), ("cvss__lte", 10.0)),
                name="vulnerability_cvss_range",
            ),
        ),
    ]
