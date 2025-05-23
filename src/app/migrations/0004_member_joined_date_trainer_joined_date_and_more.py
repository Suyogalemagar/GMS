# Generated by Django 5.1.4 on 2024-12-24 07:52

import datetime
import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0003_rename_members_member_rename_trainers_trainer_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='member',
            name='joined_date',
            field=models.DateField(auto_now_add=True, default=django.utils.timezone.now),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='trainer',
            name='joined_date',
            field=models.DateField(auto_now_add=True, default=datetime.datetime(2024, 1, 1, 0, 0)),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name='member',
            name='Name',
            field=models.CharField(max_length=100),
        ),
        migrations.AlterField(
            model_name='trainer',
            name='Name',
            field=models.CharField(max_length=100),
        ),
    ]
