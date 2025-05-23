# Generated by Django 5.1.7 on 2025-04-07 16:54

import django.db.models.deletion
import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("app", "0040_class"),
    ]

    operations = [
        migrations.CreateModel(
            name="MemberAttendance",
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
                ("date", models.DateField(default=django.utils.timezone.now)),
                (
                    "status",
                    models.CharField(
                        choices=[("Present", "Present"), ("Absent", "Absent")],
                        max_length=10,
                    ),
                ),
                (
                    "member",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="app.signup"
                    ),
                ),
            ],
        ),
    ]
