from django import forms
from .models import *
from django.contrib.auth.forms import UserCreationForm


class EnrollForm(forms.ModelForm):
    class Meta:
        model = Enroll
        fields = ('enrollnumber', 'status',)

class PaymentForm(forms.ModelForm):
    class Meta:
        model = Payment
        fields = ['user', 'enroll', 'transaction_uuid', 'amount', 'status', 'payment_method', 'signature', 'success_url', 'failure_url']

