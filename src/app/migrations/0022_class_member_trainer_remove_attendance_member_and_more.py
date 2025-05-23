# Generated by Django 5.1.4 on 2025-01-08 12:43

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0021_alter_membershipplan_price'),
    ]

    operations = [
        migrations.CreateModel(
            name='Class',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('class_name', models.CharField(max_length=100)),
                ('schedule', models.DateTimeField(blank=True, null=True)),
            ],
        ),
        migrations.CreateModel(
            name='Member',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('member_name', models.CharField(max_length=100)),
                ('member_address', models.TextField()),
                ('member_phone_number', models.CharField(max_length=15)),
                ('member_email', models.EmailField(max_length=254)),
                ('member_joined_date', models.DateField(blank=True, null=True)),
            ],
        ),
        migrations.CreateModel(
            name='Trainer',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('trainer_name', models.CharField(max_length=100)),
                ('trainer_address', models.TextField()),
                ('expertise', models.TextField()),
                ('trainer_phone_number', models.CharField(max_length=15)),
                ('trainer_email', models.EmailField(max_length=254)),
                ('trainer_joined_date', models.DateField(blank=True, null=True)),
            ],
        ),
        migrations.RemoveField(
            model_name='attendance',
            name='member',
        ),
        migrations.RemoveField(
            model_name='chatmessage',
            name='recipient',
        ),
        migrations.RemoveField(
            model_name='chatmessage',
            name='sender',
        ),
        migrations.RemoveField(
            model_name='classbooking',
            name='class_schedule',
        ),
        migrations.RemoveField(
            model_name='classbooking',
            name='member',
        ),
        migrations.RemoveField(
            model_name='classschedule',
            name='trainer',
        ),
        migrations.RemoveField(
            model_name='memberprofile',
            name='membership_plan',
        ),
        migrations.RemoveField(
            model_name='memberprofile',
            name='user',
        ),
        migrations.DeleteModel(
            name='Metrics',
        ),
        migrations.DeleteModel(
            name='Notification',
        ),
        migrations.RemoveField(
            model_name='trainerprofile',
            name='user',
        ),
        migrations.RemoveField(
            model_name='user',
            name='groups',
        ),
        migrations.RemoveField(
            model_name='user',
            name='user_permissions',
        ),
        migrations.RemoveField(
            model_name='membershipplan',
            name='description',
        ),
        migrations.RemoveField(
            model_name='membershipplan',
            name='duration_months',
        ),
        migrations.RemoveField(
            model_name='membershipplan',
            name='name',
        ),
        migrations.RemoveField(
            model_name='membershipplan',
            name='price',
        ),
        migrations.RemoveField(
            model_name='payment',
            name='amount',
        ),
        migrations.RemoveField(
            model_name='payment',
            name='payment_method',
        ),
        migrations.AddField(
            model_name='membershipplan',
            name='cost',
            field=models.FloatField(max_length=40, null=True),
        ),
        migrations.AddField(
            model_name='membershipplan',
            name='duration',
            field=models.CharField(max_length=50, null=True),
        ),
        migrations.AddField(
            model_name='membershipplan',
            name='plan',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AddField(
            model_name='payment',
            name='payment_through',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AddField(
            model_name='payment',
            name='status',
            field=models.CharField(blank=True, max_length=100),
        ),
        migrations.AlterField(
            model_name='payment',
            name='payment_date',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='member',
            name='membership_plan',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='app.membershipplan'),
        ),
        migrations.AlterField(
            model_name='payment',
            name='member',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.member'),
        ),
        migrations.AddField(
            model_name='class',
            name='trainer',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.trainer'),
        ),
        migrations.DeleteModel(
            name='Attendance',
        ),
        migrations.DeleteModel(
            name='ChatMessage',
        ),
        migrations.DeleteModel(
            name='ClassBooking',
        ),
        migrations.DeleteModel(
            name='ClassSchedule',
        ),
        migrations.DeleteModel(
            name='TrainerProfile',
        ),
        migrations.DeleteModel(
            name='User',
        ),
        migrations.DeleteModel(
            name='MemberProfile',
        ),
    ]
