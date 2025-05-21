from django.core.management.base import BaseCommand
from django.utils.timezone import localdate
from app.models import MemberAttendance, Signup 

class Command(BaseCommand):
    help = "Marks all members as Absent who haven't done attendance today"

    def handle(self, *args, **kwargs):
        today = localdate()

        # Get IDs of members who already marked Present today
        present_ids = MemberAttendance.objects.filter(date=today, status="Present").values_list('member_id', flat=True)

        # Get all other members
        absent_members = Signup.objects.exclude(id__in=present_ids)

        count = 0
        for member in absent_members:
            MemberAttendance.objects.get_or_create(
                member=member,
                date=today,
                defaults={'status': 'Absent'}
            )
            count += 1

        self.stdout.write(self.style.SUCCESS(f"{count} members marked as Absent."))
