from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from .managers import CustomUserManager
import uuid

# Create your models here.


class BaseModel(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


class User(BaseModel, AbstractBaseUser, PermissionsMixin):

    #Step 1
    USER_TYPES = (
        (1, 'SuperAdmin'),
        (2, 'Admin'),
        (3, 'User'),
    )
    uuid = models.UUIDField(default=uuid.uuid4, editable=False)
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    email = models.EmailField(unique=True)
    username = models.CharField(unique=True,max_length=100)
    password = models.CharField(max_length=100)
    show_Password = models.CharField(max_length=100,default="")
    user_type = models.IntegerField(choices=USER_TYPES)
    image = models.ImageField(upload_to='user_images/', null=True, blank=True)
    verification_token = models.CharField(max_length=100, null=True, blank=True)
    is_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    #Step2
    opt = models.BooleanField(default=False)
    bidding_sell = models.BooleanField(default=False)
    dealer = models.BooleanField(default=False)

    #Step3
    card_number = models.IntegerField()
    expiry_date = models.CharField(max_length=10)
    cvc_number = models.IntegerField()
    card_first_name = models.CharField(max_length=100)
    card_last_name = models.CharField(max_length=100)
    country_code = models.CharField(max_length=10)
    card_phone_number = models.CharField(max_length=20)
    billing_address1 = models.CharField(max_length=500)
    town_city = models.CharField(max_length=100)
    country_state = models.CharField(max_length=100)
    zipcode = models.CharField(max_length=50)
    country = models.CharField(max_length=100)


    objects = CustomUserManager()

    USERNAME_FIELD = 'username'
    # REQUIRED_FIELDS = ['name']

    def __str__(self):
        return self.email


class ContactUs(BaseModel):
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    email = models.EmailField(unique=True)
    country_code = models.CharField(max_length=10)
    phone_number = models.CharField(max_length=20)
    subject = models.CharField(max_length=100)
    message = models.TextField()