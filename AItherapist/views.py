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

def generate_token(user):
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = default_token_generator.make_token(user)
    return uid, token

def signin(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            uid, token = generate_token(user)  # Generate token for the user session
            success_url = reverse('chatbot_success', args=[uid, token])
            return redirect(success_url)  # Redirect to success page with token
        else:
            messages.error(request, 'Invalid username or password.')

    return render(request, 'signin.html')

def chatbot_success(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)

        if not default_token_generator.check_token(user, token):
            raise Exception("Invalid token")

        return render(request, 'chatbot.html')  # The actual success page
    except (User.DoesNotExist, Exception):
        messages.error(request, 'Invalid token or user.')
        return redirect('signin')

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
            uid, token = generate_token(user)
            success_url = reverse('chatbot_success', args=[uid, token])
            return redirect(success_url) # Redirect to a success page
    else:
        form = RegistrationForm()
    return render(request, 'signup.html', {'form': form})


def password_reset_request(request):
    if request.method == 'POST':
        form = PasswordResetRequestForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            try:
                reset = User.objects.get(email=email)
                # Generate token and user ID
                id = urlsafe_base64_encode(force_bytes(reset.pk))
                tok = default_token_generator.make_token(reset)
                # Redirect to the reset page with token and UID
                return redirect(reverse('password_reset_confirm', args=[id, tok]))
            except User.DoesNotExist:
                # Handle case where user does not exist
                form.add_error('email', 'Email not found')
    else:
        form = PasswordResetRequestForm()
    return render(request, 'password_reset.html', {'form': form})

def password_reset_confirm(request, uidb64, tok):
    # Decode UID and validate the token
    try:
        id = urlsafe_base64_decode(uidb64).decode()
        reset = User.objects.get(pk=id)
        if not default_token_generator.check_token(reset, tok):
            return render(request, 'invalid_token.html')  # Return an error page if token is invalid
    except (User.DoesNotExist, ValueError, TypeError, OverflowError):
        return render(request, 'invalid_token.html')

    if request.method == 'POST':
        form = SetNewPasswordForm(request.POST)
        if form.is_valid():
            # Set the new password
            reset.set_password(form.cleaned_data['password'])
            reset.save()
            # Optionally re-authenticate the user
            update_session_auth_hash(request, reset)
            messages.success(request, "Your password has been reset successfully.")
            return redirect(reverse('signin'))  # Redirect to login or a success page
    else:
        form = SetNewPasswordForm()
    
    return render(request, 'password_reset_confirm.html', {'form': form})