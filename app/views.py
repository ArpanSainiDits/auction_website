from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import *
from django.contrib.auth import authenticate, login
from rest_framework.authtoken.models import Token
from rest_framework_simplejwt.tokens import RefreshToken
from django.utils.crypto import get_random_string
from django.urls import reverse
from django.conf import settings
from .helper import *
from rest_framework.permissions import IsAuthenticated

from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_decode
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes



"""User register api"""
class RegistrationAPIView(APIView):
    def post(self, request):
        data=request.data
        # Generate a verification token
        token = get_random_string(length=32)
        data['verification_token'] = token
        serializer = CustomUserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            verification_link = request.build_absolute_uri(
            reverse('verify_email', kwargs={'token': token}))
            try:
                user_verification_email(request,verification_link,data['email'])
            except Exception as e:
                return Response({"error":"Something went wrong"}, status=status.HTTP_400_BAD_REQUEST)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)




"""User login api"""
class LoginAPIView(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            username = serializer.validated_data['username']
            password = serializer.validated_data['password']
            user = authenticate(request, username=username, password=password)
            if user:
                if user.is_verified == True:
                    login(request, user)
                    # Generate JWT tokens
                    refresh = RefreshToken.for_user(user)
                    return Response({'refresh': str(refresh),'access': str(refresh.access_token),}, status=status.HTTP_200_OK)
                else:
                    return Response({'error': 'Please verify your email.'}, status=status.HTTP_401_UNAUTHORIZED)
            else:
                return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



"""Api to change the password"""
class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]
    def put(self, request):
        user = request.user
        serializer = ChangePasswordSerializer(data=request.data)
        if serializer.is_valid():
            # Check old password
            if not user.check_password(serializer.data.get("old_password")):
                return Response({"old_password": "Wrong old password."}, status=status.HTTP_400_BAD_REQUEST)
            # Set the new password
            user.set_password(serializer.data.get("new_password"))
            user.save()
            return Response({"message": "Password updated successfully"}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    


"""Api to send forgot password link link"""
class PasswordResetView(APIView):
    def post(self, request):
        serializer = PasswordResetSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            user = User.objects.get(email=email)
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            reset_url = request.build_absolute_uri(
                reverse('password-reset-confirm', kwargs={'uid': uid, 'token': token})
            )
            email = user.email
            try:
                forgot_password_email(request,reset_url,email)
            except Exception as e:
                return Response({'error': 'Failed to send reset email'}, status=status.HTTP_400_BAD_REQUEST)
            return Response({"message": "Password reset email has been sent."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)




"""Api to change password by forgot password link"""
class PasswordResetConfirmView(APIView):
    def post(self, request, uid, token):
        try:
            uid = urlsafe_base64_decode(uid).decode()
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None
        if user is not None and default_token_generator.check_token(user, token):
            serializer = SetNewPasswordSerializer(data=request.data)
            if serializer.is_valid():
                user.set_password(serializer.validated_data['new_password'])
                user.save()
                return Response({"message": "Password has been reset successfully."}, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response({"error": "Invalid token or user ID."}, status=status.HTTP_400_BAD_REQUEST)
    



"""Contact us api"""
class Contact_us(APIView):
    def post(self,request):
        pass