# Generated by Django 5.1.4 on 2025-01-07 15:40

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0015_booking_category_membershipplan_package_packagetype_and_more'),
    ]

    operations = [
        migrations.RenameField(
            model_name='booking',
            old_name='creationdate',
            new_name='creation_date',
        ),
        migrations.RenameField(
            model_name='category',
            old_name='creationdate',
            new_name='creation_date',
        ),
        migrations.RenameField(
            model_name='member',
            old_name='Member_Joined_date',
            new_name='joined_date',
        ),
        migrations.RenameField(
            model_name='member',
            old_name='Membership_Plan',
            new_name='membership_plan',
        ),
        migrations.RenameField(
            model_name='member',
            old_name='Member_Name',
            new_name='name',
        ),
        migrations.RenameField(
            model_name='membershipplan',
            old_name='Cost',
            new_name='cost',
        ),
        migrations.RenameField(
            model_name='membershipplan',
            old_name='Plan',
            new_name='plan_name',
        ),
        migrations.RenameField(
            model_name='package',
            old_name='creationdate',
            new_name='creation_date',
        ),
        migrations.RenameField(
            model_name='package',
            old_name='packagename',
            new_name='package_type',
        ),
        migrations.RenameField(
            model_name='packagetype',
            old_name='creationdate',
            new_name='creation_date',
        ),
        migrations.RenameField(
            model_name='paymenthistory',
            old_name='creationdate',
            new_name='creation_date',
        ),
        migrations.RenameField(
            model_name='signup',
            old_name='creationdate',
            new_name='creation_date',
        ),
        migrations.RenameField(
            model_name='trainer',
            old_name='Trainer_Joined_date',
            new_name='joined_date',
        ),
        migrations.RenameField(
            model_name='trainer',
            old_name='Trainer_Name',
            new_name='name',
        ),
        migrations.RemoveField(
            model_name='booking',
            name='bookingnumber',
        ),
        migrations.RemoveField(
            model_name='category',
            name='categoryname',
        ),
        migrations.RemoveField(
            model_name='member',
            name='Member_Address',
        ),
        migrations.RemoveField(
            model_name='member',
            name='Member_Email',
        ),
        migrations.RemoveField(
            model_name='member',
            name='Member_Phone_number',
        ),
        migrations.RemoveField(
            model_name='membershipplan',
            name='Duration',
        ),
        migrations.RemoveField(
            model_name='package',
            name='packageduration',
        ),
        migrations.RemoveField(
            model_name='package',
            name='titlename',
        ),
        migrations.RemoveField(
            model_name='packagetype',
            name='packagename',
        ),
        migrations.RemoveField(
            model_name='trainer',
            name='Expertise',
        ),
        migrations.RemoveField(
            model_name='trainer',
            name='Trainer_Address',
        ),
        migrations.RemoveField(
            model_name='trainer',
            name='Trainer_Email',
        ),
        migrations.RemoveField(
            model_name='trainer',
            name='Trainer_Phone_number',
        ),
        migrations.AddField(
            model_name='booking',
            name='booking_number',
            field=models.CharField(blank=True, max_length=100),
        ),
        migrations.AddField(
            model_name='category',
            name='name',
            field=models.CharField(blank=True, max_length=200),
        ),
        migrations.AddField(
            model_name='member',
            name='address',
            field=models.TextField(blank=True),
        ),
        migrations.AddField(
            model_name='member',
            name='email',
            field=models.EmailField(blank=True, max_length=254),
        ),
        migrations.AddField(
            model_name='member',
            name='phone_number',
            field=models.CharField(blank=True, max_length=15),
        ),
        migrations.AddField(
            model_name='package',
            name='duration',
            field=models.CharField(blank=True, max_length=50),
        ),
        migrations.AddField(
            model_name='package',
            name='title',
            field=models.CharField(blank=True, max_length=200),
        ),
        migrations.AddField(
            model_name='packagetype',
            name='name',
            field=models.CharField(blank=True, max_length=200),
        ),
        migrations.AddField(
            model_name='trainer',
            name='address',
            field=models.TextField(blank=True),
        ),
        migrations.AddField(
            model_name='trainer',
            name='email',
            field=models.EmailField(blank=True, max_length=254),
        ),
        migrations.AddField(
            model_name='trainer',
            name='phone_number',
            field=models.CharField(blank=True, max_length=15),
        ),
        migrations.AlterField(
            model_name='category',
            name='status',
            field=models.CharField(blank=True, max_length=300),
        ),
        migrations.AlterField(
            model_name='package',
            name='description',
            field=models.TextField(blank=True),
        ),
        migrations.AlterField(
            model_name='package',
            name='price',
            field=models.FloatField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='signup',
            name='address',
            field=models.CharField(blank=True, max_length=200),
        ),
        migrations.AlterField(
            model_name='signup',
            name='city',
            field=models.CharField(blank=True, max_length=150),
        ),
        migrations.AlterField(
            model_name='signup',
            name='mobile',
            field=models.CharField(blank=True, max_length=15),
        ),
        migrations.AlterField(
            model_name='signup',
            name='state',
            field=models.CharField(blank=True, max_length=150),
        ),
        migrations.CreateModel(
            name='Class',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100)),
                ('schedule', models.DateTimeField(blank=True, null=True)),
                ('trainer', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='app.trainer')),
            ],
        ),
        migrations.DeleteModel(
            name='Classe',
        ),
        migrations.AddField(
            model_name='membershipplan',
            name='duration',
            field=models.CharField(blank=True, max_length=50),
        ),
        migrations.AddField(
            model_name='trainer',
            name='expertise',
            field=models.TextField(blank=True),
        ),
    ]
