from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
class Trainer(models.Model):
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('on_leave', 'On Leave'),
        ('inactive', 'Inactive'),
    ]
    
    user = models.OneToOneField(User, on_delete=models.CASCADE, null=True, blank=True)
    first_name = models.CharField(max_length=100, null=True)
    last_name = models.CharField(max_length=100, null=True)
    email = models.EmailField(null=True, blank=True)
    phone = models.CharField(max_length=15)
    address = models.TextField()
    experience = models.PositiveIntegerField(null=True, blank=True)
    is_verified = models.BooleanField(default=False)
    status = models.CharField(
        max_length=10,
        choices=STATUS_CHOICES,
        default='active'  # Set default to active
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.user.username if self.user else "No User"

# Category Model
class Category(models.Model):
    categoryname = models.CharField(max_length=200, null=True)
    status = models.CharField(max_length=300, null=True)
    creationdate = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.categoryname

# Package Type Model
class Packagetype(models.Model):
    category = models.ForeignKey(Category, on_delete=models.CASCADE, null=True)
    packagename = models.CharField(max_length=200, null=True)
    creationdate = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.packagename

# Signup Model: Stores additional user information
class Signup(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, null=True)  # One-to-One link with User
    mobile = models.CharField(max_length=15, null=True)
    state = models.CharField(max_length=150, null=True)
    city = models.CharField(max_length=150, null=True)
    address = models.CharField(max_length=200, null=True)
    creationdate = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.user.username  

# Package Model
class Package(models.Model):
    category = models.ForeignKey(Category, on_delete=models.CASCADE, null=True)
    packagename = models.ForeignKey(Packagetype, on_delete=models.CASCADE, null=True)
    titlename = models.CharField(max_length=200, null=True)
    packageduration = models.CharField(max_length=50, null=True)
    price = models.DecimalField(max_digits=10, decimal_places=2, null=True)  
    description = models.TextField(null=True)
    creationdate = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.titlename

# Enroll Model

class Enroll(models.Model):
    STATUS = (
        (1, "Paid"),
        (0, "Unpaid"),
    )
    package = models.ForeignKey(Package, on_delete=models.CASCADE, null=True, blank=True)
    register = models.ForeignKey(Signup, on_delete=models.CASCADE, null=True, blank=True)
    enrollnumber = models.CharField(max_length=100, null=True, blank=True)
    status = models.IntegerField(choices=STATUS, default=1)
    creationdate = models.DateTimeField(auto_now_add=True)

    @property
    def payment_status_display(self):
        return self.get_status_display()

# Payment History Model
STATUS = (
    (1, "Paid"),
    (0, "Unpaid"),
)
class Paymenthistory(models.Model):
    user = models.ForeignKey(Signup, on_delete=models.CASCADE, null=True, blank=True)
    enroll = models.ForeignKey(Enroll, on_delete=models.CASCADE, null=True, blank=True)
    price = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    status = models.IntegerField(choices=STATUS, default=1)
    payment_method = models.CharField(max_length=50, default="eSewa")  # Add payment_method field
    creationdate = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Paymenthistory {self.enroll} - {self.user.username if self.user else 'Unknown'}"

# Payment Model
class Payment(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    enroll = models.ForeignKey(Enroll, on_delete=models.CASCADE, null=True, blank=True)
    transaction_uuid = models.CharField(max_length=255, unique=True)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    status = models.IntegerField(choices=STATUS, default=1)
    payment_method = models.CharField(max_length=50, default="eSewa")
    signature = models.CharField(max_length=255)
    success_url = models.URLField()
    failure_url = models.URLField()
    creationdate = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"Payment {self.transaction_uuid} - {self.user.username if self.user else 'Unknown'}"
    
    def get_status_display(self):
        # You already have status choices, so this will automatically return a display value
        return dict(STATUS).get(self.status, 'Unknown Status')  # Ensure it's readable

class Class(models.Model):
    name = models.CharField(max_length=100)
    trainer = models.ForeignKey(Trainer, on_delete=models.SET_NULL, null=True, blank=True)
    schedule = models.CharField(max_length=255, default="To be determined")  # e.g., "Monday, Wednesday 6:00 PM"
    capacity = models.PositiveIntegerField()
    members = models.ManyToManyField(Signup, blank=True)
    creationdate = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} - {self.trainer.first_name if self.trainer else 'Unassigned'}"
class MemberAttendance(models.Model):
    member = models.ForeignKey('Signup', on_delete=models.CASCADE)
    date = models.DateField(default=timezone.now)
    time = models.TimeField(default=timezone.now)
    status = models.CharField(max_length=10, choices=[('Present', 'Present'), ('Absent', 'Absent')])

    def __str__(self):
        return f"{self.member.user.username} - {self.date} - {self.status}"