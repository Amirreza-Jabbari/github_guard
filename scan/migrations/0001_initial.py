# Generated by Django 5.1.1 on 2025-03-01 00:52

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="Scan",
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
                ("scan_id", models.CharField(max_length=64, unique=True)),
                ("repo_url", models.URLField()),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("queued", "Queued"),
                            ("in_progress", "In Progress"),
                            ("completed", "Completed"),
                            ("failed", "Failed"),
                        ],
                        default="queued",
                        max_length=20,
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("completed_at", models.DateTimeField(blank=True, null=True)),
            ],
        ),
        migrations.CreateModel(
            name="ScanResult",
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
                ("commit_hash", models.CharField(max_length=40)),
                ("branch", models.CharField(max_length=100)),
                ("risk_type", models.CharField(max_length=100)),
                ("file_path", models.CharField(max_length=255)),
                ("snippet", models.TextField()),
                ("timestamp", models.DateTimeField()),
                ("remediation", models.TextField()),
                (
                    "scan",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="results",
                        to="scan.scan",
                    ),
                ),
            ],
        ),
    ]
