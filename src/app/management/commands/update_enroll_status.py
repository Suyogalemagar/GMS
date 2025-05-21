from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta
from app.models import Enroll

def parse_duration(duration_str):
    """
    Parses duration strings like:
    - "7 days"
    - "1 month"
    - "3 months"
    - "1 year"
    Returns a timedelta approximation.
    """
    if not duration_str:
        return None
    
    duration_str = duration_str.lower().strip()
    print(duration_str)
    number, unit = duration_str.split()  # naive split; assumes format "number unit"
    number = int(number)

    if unit.startswith('day'):
        return timedelta(days=number)
    elif unit.startswith('month'):
        return timedelta(days=30 * number)  # approximate
    elif unit.startswith('year'):
        return timedelta(days=365 * number)  # approximate
    else:
        return None

class Command(BaseCommand):
    help = 'Change Enroll status to unpaid based on package duration'

    def handle(self, *args, **kwargs):
        now = timezone.now()
        updated_count = 0

        enrolls = Enroll.objects.filter(status=1).select_related('package')
        for enroll in enrolls:
            duration = parse_duration(enroll.package.packageduration)
            if duration:
                expire_date = enroll.creationdate + duration
                if expire_date < now:
                    enroll.status = 0  # unpaid
                    enroll.save()
                    updated_count += 1

        self.stdout.write(f'Updated {updated_count} enroll(s) to Unpaid based on package duration.')
