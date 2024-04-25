from django.shortcuts import render, redirect
from .forms import RegistrationForm, PasswordResetRequestForm,SetNewPasswordForm
from django.contrib.auth import authenticate, login
from django.contrib import messages
from django.urls import reverse
from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode,urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.contrib.auth import update_session_auth_hash

def signin(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('chatbot_success')
        else:
            messages.error(request, 'Invalid username or password.')
    return render(request, 'signin.html')

def signup(request):
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            # Check if passwords match
            password1 = form.cleaned_data.get('password1')
            password2 = form.cleaned_data.get('password2')
            # Passwords match, proceed with user registration
            user = form.save()
            # Log in the user after registration
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password1')
            user = authenticate(username=username, password=password)
            login(request, user)
            return redirect('chatbot_success')  # Redirect to a success page
    else:
        form = RegistrationForm()
    return render(request, 'signup.html', {'form': form})


def chatbot_success(request):
  return render(request, 'chatbot.html')

def password_reset_request(request):
    if request.method == 'POST':
        form = PasswordResetRequestForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            try:
                user = User.objects.get(email=email)
                # Generate token and user ID
                uid = urlsafe_base64_encode(force_bytes(user.pk))
                token = default_token_generator.make_token(user)
                # Redirect to the reset page with token and UID
                return redirect(reverse('password_reset_confirm', args=[uid, token]))
            except User.DoesNotExist:
                # Handle case where user does not exist
                form.add_error('email', 'Email not found')
    else:
        form = PasswordResetRequestForm()
    return render(request, 'password_reset.html', {'form': form})

def password_reset_confirm(request, uidb64, token):
    # Decode UID and validate the token
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)
        if not default_token_generator.check_token(user, token):
            return render(request, 'invalid_token.html')  # Return an error page if token is invalid
    except (User.DoesNotExist, ValueError, TypeError, OverflowError):
        return render(request, 'invalid_token.html')

    if request.method == 'POST':
        form = SetNewPasswordForm(request.POST)
        if form.is_valid():
            # Set the new password
            user.set_password(form.cleaned_data['password'])
            user.save()
            # Optionally re-authenticate the user
            update_session_auth_hash(request, user)
            return redirect(reverse('chatbot_success'))  # Redirect to login or a success page
    else:
        form = SetNewPasswordForm()
    
    return render(request, 'password_reset_confirm.html', {'form': form})