import datetime



from django.contrib.auth.models import  PermissionsMixin
from django.core.validators import MaxLengthValidator, MinLengthValidator

from django.contrib.auth.validators import UnicodeUsernameValidator

import unicodedata

from django.contrib.auth import password_validation
from django.contrib.auth.hashers import (
    check_password
)
from django.db import models

from django.utils.translation import gettext_lazy as _

from django.contrib import auth


class BaseUserManager(models.Manager):

    @classmethod
    def get_by_natural_key(self, MobileNumber):
        return self.get(**{self.model.USERNAME_FIELD: MobileNumber})
class UserManager(BaseUserManager):
    use_in_migrations = True

    def _create_user(self, MobileNumber, otp, **extra_fields):
        """
        Create and save a user with the given username, email, and password.
        """
        if not MobileNumber:
            raise ValueError('The given username must be set')

        mobile = self.model.normalize_MobileNumber(MobileNumber)
        user = self.model(MobileNumber=mobile, **extra_fields)
        user.set_otp(otp)
        user.save(using=self._db)
        return user

    def create_user(self, MobileNumber,otp=None ,**extra_fields):
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)
        return self._create_user(MobileNumber, otp, **extra_fields)

    def create_superuser(self, MobileNumber, otp=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self._create_user(MobileNumber,otp, **extra_fields)

    def with_perm(self, perm, is_active=True, include_superusers=True, backend=None, obj=None):
        if backend is None:
            backends = auth._get_backends(return_tuples=True)
            if len(backends) == 1:
                backend, _ = backends[0]
            else:
                raise ValueError(
                    'You have multiple authentication backends configured and '
                    'therefore must provide the `backend` argument.'
                )
        elif not isinstance(backend, str):
            raise TypeError(
                'backend must be a dotted import path string (got %r).'
                % backend
            )
        else:
            backend = auth.load_backend(backend)
        if hasattr(backend, 'with_perm'):
            return backend.with_perm(
                perm,
                is_active=is_active,
                include_superusers=include_superusers,
                obj=obj,
            )
        return self.none()



class AbstractBaseUser(models.Model):
    otp = models.CharField(_('OTP'), max_length=10)
    last_login = models.DateTimeField(_('last login'), blank=True, null=True)

    is_active = True

    REQUIRED_FIELDS = ['otp']

    # Stores the raw password if set_password() is called so that it can
    # be passed to password_changed() after the model is saved.
    _otp = None

    class Meta:
        abstract = True

    def __str__(self):
        return self.get_MobileNumber()

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        if self._otp is not None:
            password_validation.password_changed(self._otp, self)
            self._otp = None

    def get_MobileNumber(self):
        """Return the username for this User."""
        return getattr(self, self.USERNAME_FIELD)

    def clean(self):
        setattr(self, self.USERNAME_FIELD, self.normalize_(self.get_MobileNumber()))

    def natural_key(self):
        return (self.get_MobileNumber(),)

    @property
    def is_anonymous(self):
        """
        Always return False. This is a way of comparing User objects to
        anonymous users.
        """
        return False

    @property
    def is_authenticated(self):
        """
        Always return True. This is a way to tell if the user has been
        authenticated in templates.
        """
        return True



    def check_otp(self, otp):
        """
        Return a boolean of whether the raw_password was correct. Handles
        hashing formats behind the scenes.
        """

        return check_password(otp, self.otp)



    @classmethod
    def normalize_MobileNumber(cls, MobileNumber):
        return unicodedata.normalize('NFKC', MobileNumber) if isinstance(MobileNumber, str) else MobileNumber


class AbstractUser(AbstractBaseUser, PermissionsMixin):


    username_validator = UnicodeUsernameValidator()

    mobileNumber = models.CharField(
        ('mobile'),
        max_length=10,
        unique=True,
        validators=[MinLengthValidator(10),MaxLengthValidator(10)],
        error_messages={
            'unique': ("A user with that username already exists."),
        },
    )

    otp = models.CharField(('OTP'), max_length=10, blank=False)

    is_staff = models.BooleanField(
        ('staff status'),
        default=False,
        help_text=('Designates whether the user can log into this admin site.'),
    )
    is_active = models.BooleanField(
        ('active'),
        default=True,
        help_text=(
            'Designates whether this user should be treated as active. '
            'Unselect this instead of deleting accounts.'
        ),
    )
    date_joined = models.DateTimeField(('date joined'), default=datetime.datetime.now())

    objects = UserManager()

    USERNAME_FIELD = 'mobile Number'
    REQUIRED_FIELDS = ['mobileNumber', 'otp']

    class Meta:
        verbose_name = ('user')
        verbose_name_plural = ('users')
        abstract = True

    def get_short_name(self):
        """Return the short name for the user."""
        return self.mobileNumber
class User1(AbstractUser):

    class Meta(AbstractUser.Meta):
        swappable = 'AUTH_USER_MODEL'





# Create your models here.
