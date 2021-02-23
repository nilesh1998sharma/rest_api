
from __future__ import unicode_literals
from django.contrib.auth.base_user import BaseUserManager, AbstractBaseUser
from django.core.validators import RegexValidator
import binascii
import os

from django.db import models
from django.conf import settings
from django.utils.translation import gettext_lazy as _


class UserManager(BaseUserManager):
    def create_user(self, phone, password=None, is_staff=False, is_active=True, is_admin=False):
        if not phone:
            raise ValueError('users must have a phone number')
        if not password:
            raise ValueError('user must have a password')

        user_obj = self.model(
            phone=phone
        )
        user_obj.set_password(password)
        user_obj.staff = is_staff
        user_obj.admin = is_admin
        user_obj.active = is_active
        user_obj.save(using=self._db)
        return user_obj

    def create_staffuser(self, phone, password=None):
        user = self.create_user(
            phone,
            password=password,
            is_staff=True,

        )
        return user

    def create_superuser(self, phone, password=None):
        user = self.create_user(
            phone,
            password=password,
            is_staff=True,
            is_admin=True,

        )
        return user
class User(AbstractBaseUser):
    phone_regex = RegexValidator(regex=r'^\+?1?\d{9,14}$',
                                 message="Phone number must be entered in the format: '+999999999'. Up to 14 digits allowed.")
    phone = models.CharField(validators=[phone_regex], max_length=17, unique=True)
    name = models.CharField(max_length=20, blank=True, null=True)


    first_login = models.BooleanField(default=False)
    active = models.BooleanField(default=True)
    staff = models.BooleanField(default=False)
    admin = models.BooleanField(default=False)
    timestamp = models.DateTimeField(auto_now_add=True)

    USERNAME_FIELD = 'phone'
    REQUIRED_FIELDS = []

    objects = UserManager()

    def __str__(self):
        return self.phone

    def get_full_name(self):
        return self.phone

    def get_short_name(self):
        return self.phone

    def has_perm(self, perm, obj=None):
        return True

    def has_module_perms(self, app_label):
        return True

    @property
    def is_staff(self):
        return self.staff

    @property
    def is_admin(self):
        return self.admin

    @property
    def is_active(self):
        return self.active
class PhoneOTP(models.Model):
    phone_regex = RegexValidator(regex=r'^\+?1?\d{9,14}$',
                                 message="Phone number must be entered in the format: '+999999999'. Up to 14 digits allowed.")
    phone = models.CharField(validators=[phone_regex], max_length=17, unique=True)
    otp = models.CharField(max_length=9, blank=True, null=True)
    count = models.IntegerField(default=0, help_text='Number of otp sent')
    logged = models.BooleanField(default=False, help_text='If otp verification got successful')
    forgot = models.BooleanField(default=False, help_text='only true for forgot password')
    forgot_logged = models.BooleanField(default=False, help_text='Only true if validdate otp forgot get successful')
    def __str__(self):
        return self.otp+"  is sent to"+self.phone
class UserInfo(models.Model):
    Gender=(
        ('Male',('Male')),
        ('Female',('Female')),
        ('Other',('Other'))


    )
    user=models.ForeignKey(User,on_delete=models.CASCADE)
    name =models.CharField(max_length=70)
    address = models.CharField(max_length=100)
    email=models.EmailField()
    gender=models.CharField(max_length=20,choices=Gender,default=None)
        #class Meta:
        #unique_together=(('user','name'),('user','address'),('user','gender'))


    def __str__(self):
        return self.name+"- ---"+self.user.phone
class Group(models.Model):
    user=models.ForeignKey(User,on_delete=models.CASCADE)
    Groupname = models.CharField(max_length=50)

    def __str__(self):
        return self.Groupname+"- ---"+self.user.phone

class Members(models.Model):

    group=models.ForeignKey(Group,on_delete=models.CASCADE)
    name=models.CharField(max_length=40)
    member=models.ForeignKey(UserInfo,on_delete=models.CASCADE)
    relation = models.CharField(max_length=40)
    def __str__(self):
        return self.group.Groupname+"---"+ self.member.name+"---"+self.relation

#class Relation(models.Model):
 #   user=models.ForeignKey(User,on_delete=models.CASCADE)
  #  member=models.ForeignKey(Members,on_delete=models.CASCADE)
   # relation=models.CharField(max_length=40)






# Create your models here.
