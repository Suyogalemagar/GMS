from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone

# Create your models here.
class Trainer(models.Model):
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    email = models.EmailField(unique=True)
    phone = models.CharField(max_length=15)
    address = models.TextField()
    experience = models.IntegerField(help_text="Years of experience")
    is_verified = models.BooleanField(default=False)  # to track if the trainer is verified
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.first_name} {self.last_name} ({self.email})"
    
class Category(models.Model):
    categoryname = models.CharField(max_length=200, null=True)
    status = models.CharField(max_length=300, null=True)
    creationdate = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.categoryname

class Packagetype(models.Model):
    category = models.ForeignKey(Category, on_delete=models.CASCADE, null=True)
    packagename = models.CharField(max_length=200, null=True)
    creationdate = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.packagename

class Signup(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True)
    mobile = models.CharField(max_length=15, null=True)
    state = models.CharField(max_length=150, null=True)
    city = models.CharField(max_length=150, null=True)
    address = models.CharField(max_length=200, null=True)
    creationdate = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.user.first_name

class Regtrainer(models.Model):
    trainer = models.ForeignKey(User, on_delete=models.CASCADE, null=True)
    mobile = models.CharField(max_length=15, null=True)
    state = models.CharField(max_length=150, null=True)
    city = models.CharField(max_length=150, null=True)
    address = models.CharField(max_length=200, null=True)
    creationdate = models.DateTimeField(auto_now_add=True)
    experties = models.CharField(max_length=200, null=True)

    def __str__(self):
        return self.trainer.first_name  # Corrected reference


class Package(models.Model):
    category = models.ForeignKey(Category, on_delete=models.CASCADE, null=True)
    packagename = models.ForeignKey(Packagetype, on_delete=models.CASCADE, null=True)
    titlename = models.CharField(max_length=200, null=True)
    packageduration = models.CharField(max_length=50, null=True)
    price = models.CharField(max_length=200, null=True)
    description = models.CharField(max_length=200, null=True)
    creationdate = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.titlename

STATUS = ((1, "Not Updated Yet"), (2, "Partial Payment"), (3, 'Full Payment'))
class Booking(models.Model):
    package = models.ForeignKey(Package, on_delete=models.CASCADE, null=True, blank=True)
    register = models.ForeignKey(Signup, on_delete=models.CASCADE, null=True, blank=True)
    bookingnumber = models.CharField(max_length=100, null=True, blank=True)
    status = models.IntegerField(choices=STATUS, default=1)
    creationdate = models.DateTimeField(auto_now_add=True)

class Paymenthistory(models.Model):
    user = models.ForeignKey(Signup, on_delete=models.CASCADE, null=True, blank=True)
    booking = models.ForeignKey(Booking, on_delete=models.CASCADE, null=True, blank=True)
    price = models.CharField(max_length=100, null=True, blank=True)
    status = models.IntegerField(choices=STATUS, default=1)
    creationdate = models.DateTimeField(auto_now_add=True)




# models.py
# models.py
from django.db import models

class Payment(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    booking=models.ForeignKey(Booking, on_delete=models.CASCADE, null=True, blank=True)
    transaction_uuid = models.CharField(max_length=255, unique=True)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    status = models.IntegerField(choices=STATUS, default=1)
    payment_method = models.CharField(max_length=50, default="eSewa")  
    signature = models.CharField(max_length=255)
    success_url = models.URLField()
    failure_url = models.URLField()
    creationdate = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"Payment {self.transaction_uuid} - {self.user.first_name if self.user else 'Unknown'}"
