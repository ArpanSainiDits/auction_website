from django.urls import path
from .views import *
from .helper import VerifyEmailView
urlpatterns = [
    path('register',RegistrationAPIView.as_view(),name="register"),
    path('login',LoginAPIView.as_view(),name="login"),
    path('verify-email/<str:token>/', VerifyEmailView.as_view(), name='verify_email'),
    path('change-password/', ChangePasswordView.as_view(), name='change-password'),
    path('password-reset/', PasswordResetView.as_view(), name='password-reset'),
    path('password-reset-confirm/<uid>/<token>/', PasswordResetConfirmView.as_view(), name='password-reset-confirm'),

]


