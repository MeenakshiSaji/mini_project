from django.urls import path
from . import views
from .views import CustomPasswordResetView, CustomPasswordResetConfirmView

urlpatterns = [
  path('signin/', views.signin, name='signin'),
  path('signup/', views.signup, name='signup'),
  path('chatbot_success/', views.chatbot_success, name='chatbot_success'),
  path('password/reset/', CustomPasswordResetView.as_view(), name='password_reset'),
  path('password/reset/confirm/<uidb64>/<token>/', CustomPasswordResetConfirmView.as_view(), name='password_reset_confirm'),
  path('password-reset/', views.password_reset_request, name='password_reset_request'),
  path('password-reset/<uidb64>/<token>/', views.password_reset_confirm, name='password_reset_confirm')

]
