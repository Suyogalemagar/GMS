from django import forms
from .models import *
from django.contrib.auth.forms import UserCreationForm


class BookingForm(forms.ModelForm):
    class Meta:
        model = Booking
        fields = ('bookingnumber', 'status',)

# forms.py


class PaymentForm(forms.ModelForm):
    class Meta:
        model = Payment
        fields = ['user', 'booking', 'transaction_uuid', 'amount', 'status', 'payment_method', 'signature', 'success_url', 'failure_url']
