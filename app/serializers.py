# accounts/serializers.py
from rest_framework import serializers
from .models import *
from django.contrib.auth.hashers import make_password
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError



class CustomUserSerializer(serializers.ModelSerializer):
    def create(self, validated_data):
        password = validated_data.pop('password')
        if len(password) < 8:
            raise serializers.ValidationError({"new_password": "Password must be at least 8 characters long."})
        validated_data['password'] = make_password(password)       
        return super(CustomUserSerializer, self).create(validated_data) 
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email','username','password','user_type','is_active','verification_token','cvc_number','card_first_name','card_last_name','country_code','card_phone_number','billing_address1','town_city','country_state','zipcode','country']
        # fields = ['first_name', 'last_name', 'email','username','password','user_type','is_active','verification_token']
        # extra_kwargs = {'password': {'write_only': True}}



class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(required=True)
    password = serializers.CharField(required=True, write_only=True)




class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)
    confirm_password = serializers.CharField(required=True)
    def validate(self, data):
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError({"password": "New passwords don't match."})
        # Check for minimum password length
        if len(data['new_password']) < 8:
            raise serializers.ValidationError({"new_password": "Password must be at least 8 characters long."})
        # try:
        #     validate_password(data['new_password'])
        # except ValidationError as e:
        #     raise serializers.ValidationError({"new_password": list(e.messages)})
        return data
    


class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()
    def validate_email(self, value):
        # Check if email exists in the system
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError("No user found with this email address.")
        return value
    


class SetNewPasswordSerializer(serializers.Serializer):
    new_password = serializers.CharField(required=True)
    confirm_password = serializers.CharField(required=True)
    def validate(self, data):
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError({"password": "New passwords don't match."})
        # Check for minimum password length
        if len(data['new_password']) < 8:
            raise serializers.ValidationError({"new_password": "Password must be at least 8 characters long."})
        # try:
        #     validate_password(data['new_password'])
        # except ValidationError as e:
        #     raise serializers.ValidationError({"new_password": list(e.messages)})
        return data
    


class ContactUsSerializer(serializers.ModelSerializer):
    class Meta:
        model = ContactUs
        fields = '__all__'





