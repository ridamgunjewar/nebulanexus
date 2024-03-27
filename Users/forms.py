from django import forms

class OTPForm(forms.Form):
    otp = forms.IntegerField(label='Enter OTP')
