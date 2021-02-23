from rest_framework.authtoken.models import Token
from .models import *
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers
from django.contrib.auth import authenticate

class LoginSerializer(serializers.ModelSerializer):
    class Meta:
        model=User
        fields=('id','phone','password')
        extra_kwargs = {'password': {'write_only': True}, }

    def create(self, validated_data):
        user1 = User.objects.create_user(**validated_data)
        Token.objects.create(user=user1)
        return user1
class UserInfoSerializer(serializers.ModelSerializer):
    class Meta:
        model=UserInfo
        fields='__all__'
class GroupSerializer(serializers.ModelSerializer):
    class Meta:
        model=Group
        fields='__all__'
class MemberSerializer(serializers.ModelSerializer):
    class Meta:
        model=Members
        fields='__all__'



class AuthTokenSerializer(serializers.Serializer):
    phone = serializers.CharField(
        label=_("phone"),
        write_only=True
    )
    password = serializers.CharField(
        label=_("Password"),
        style={'input_type': 'password'},
        trim_whitespace=False,
        write_only=True
    )
    token = serializers.CharField(
        label=_("Token"),
        read_only=True
    )

    def validate(self, attrs):
        phone = attrs.get('phone')
        password = attrs.get('password')

        if phone and password:
            user = authenticate(request=self.context.get('request'),
                                phone=phone, password=password)
            print(phone,password)

            if not user:
                msg = _('Unable to log in with provided credentials.')
                raise serializers.ValidationError(msg, code='authorization')
        else:
            msg = _('Must include "phone" and "password".')
            raise serializers.ValidationError(msg, code='authorization')

        attrs['user'] = user
        return attrs






