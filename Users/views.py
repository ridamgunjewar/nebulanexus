import random

from django.contrib.auth import authenticate, login
from django.core.mail import send_mail
from django.shortcuts import render, redirect
from django.http import HttpResponse, HttpResponseRedirect
from django.contrib.auth.models import User
from djoser import email
from .models import UserProfile
from .forms import OTPForm

# Function to generate a 4-digit OTP
def generate_otp():
    return random.randint(1000, 9999)

# Sign-up page
def SignupPage(request):
    if request.method == 'POST':
        first_name = request.POST.get('firstname','')
        last_name = request.POST.get('lastname', '')  # Set default value if last name is not provided
        username = request.POST.get('username')
        email = request.POST.get('email')
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')

        if User.objects.filter(username=username).exists() or User.objects.filter(email=email).exists():
            return HttpResponse(
                "A user with the same username or email already exists. Please choose a different username or email.")

        if password1 != password2:
            return HttpResponse("Your password and confirm password are not the same!")
        else:
            # Generate OTP and save it to the user's profile
            otp = generate_otp()
            user = User.objects.create_user(username=username, email=email, password=password1, first_name=first_name, last_name=last_name)
            user_profile = UserProfile.objects.create(user=user, otp=otp)
            user_profile.save()

            # Send OTP to the user's email
            send_mail(
                'Verification OTP',
                f'Your OTP is: {otp}',
                'gunjewarridam@gmail.com',  # From email address
                [email],
                fail_silently=True,  # Set to True to suppress errors
            )

            # Redirect to OTP verification page
            return redirect('verify-otp', profile_id=user_profile.id)

    return render(request, 'signup.html')


# OTP verification page
def VerifyOTP(request, profile_id):
    user_profile = UserProfile.objects.get(pk=profile_id)
    if request.method == 'POST':
        form = OTPForm(request.POST)
        if form.is_valid():
            if int(form.cleaned_data['otp']) == user_profile.otp:
                user_profile.user.is_active = True
                user_profile.user.save()
                user_profile.save()
                return HttpResponseRedirect('/login/')
            else:
                return HttpResponse("Invalid OTP. Please try again.")
    else:
        form = OTPForm()

    return render(request, 'verify_otp.html', {'form': form})

def LoginPage(request, user=None):
    if request.method == 'POST':
        username = request.POST.get('username')
        pass1 = request.POST.get('pass')

        user = authenticate(request, username=username, password=pass1)
        print(user, pass1)
        if user is not None:
            login(request, user)
            return redirect('/homepage/')
        else:
            return render(request, 'login.html', {'error': "Wrong credentials"})

    return render(request, 'login.html', {'user': user})

def homepage(request):
    return render(request, "index.html")


def password_reset_form(request):
    return render(request, 'password_reset_form.html')