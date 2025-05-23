# Generated by Django 5.1.7 on 2025-05-14 07:24

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("app", "0052_remove_message_room_remove_message_sender_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="trainer",
            name="profile_photo",
            field=models.ImageField(blank=True, null=True, upload_to="trainer_photos/"),
        ),
        migrations.AddField(
            model_name="trainer",
            name="profile_url",
            field=models.URLField(blank=True, null=True),
        ),
    ]
