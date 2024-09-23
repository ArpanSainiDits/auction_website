from django.core.mail import send_mail
from auction_website import settings
from django.core.mail import BadHeaderError
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import User


"""Send verification email to user"""
def user_verification_email(request,message,user_email):
    subject = "Verify your email to Auction website"
    message = f'Click the link to verify your email: {message}'
    
    email_from = settings.EMAIL_HOST_USER
    recipient_list = [user_email]
    send_mail(subject, message, email_from, recipient_list)



"""User email verification  api """
class VerifyEmailView(APIView):
    def get(self, request, token):
        try:
            user = User.objects.get(verification_token=token)
            user.is_verified = True
            user.verification_token = None  # Clear the token
            user.save()
            return Response({"message": "Email verified successfully!"}, status=status.HTTP_200_OK)
        except user.DoesNotExist:
            return Response({"error": "Invalid token!"}, status=status.HTTP_400_BAD_REQUEST)



"""To send forgot password email"""
def forgot_password_email(request,reset_url,email):
    subject = "Password reset email to Auction website"
    message = f'Use the following link to reset your password: {reset_url}'
    email_from = settings.EMAIL_HOST_USER
    recipient_list = [email]
    send_mail(subject, message, email_from, recipient_list)