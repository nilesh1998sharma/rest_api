import random
from django.contrib.auth import authenticate
from django.db.models import Q
from rest_framework import parsers, renderers
from rest_framework.authtoken.serializers import AuthTokenSerializer
from rest_framework.compat import coreapi, coreschema
from rest_framework.decorators import action
from rest_framework.generics import ListAPIView
from rest_framework.response import Response
from rest_framework.schemas import ManualSchema
from rest_framework.schemas import coreapi as coreapi_schema
from rest_framework.views import APIView
from rest_framework import viewsets, status
from .serializers import *
from django.conf import settings
from django.core.mail import send_mail

from rest_framework.filters import (SearchFilter)





class Login(APIView):
    queryset = User.objects.all()
    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):
        phone = request.data.get('phone')
        password = request.data.get('password')

        if phone and password:
            phone1 = str(phone)
            user = User.objects.filter(phone__iexact=phone1)
            if user:
                user1 = authenticate(phone=phone1, password=password)
                try:
                    if user1.is_active:
                        old = PhoneOTP.objects.filter(phone__iexact=phone1)
                        old.delete()
                        code = send_otp(phone)
                        if code:
                            PhoneOTP.objects.create(phone=phone, otp=code)
                            return Response({
                                'data': user1.id,
                                'status': True,
                                'detail': 'User Authenticated'
                            })


                        else:
                            return Response({
                                'status': False,
                                'detail': 'Failed to Load Otp'
                            })

                    else:
                        return Response({
                            'status': False,
                            'detail': 'Invalid Password'
                        })
                except:
                    return Response({
                        'status': False,
                        'detail': 'Invalid Password'
                    })
            else:
                user2 = User.objects.create_user(phone=phone, password=password)
                user2.save()
                code = send_otp(phone)
                if code:
                    PhoneOTP.objects.create(phone=phone, otp=code)
                    Token.objects.get_or_create(user=user2)
                    return Response({
                        'data': user2.id,
                        'status': True,
                        'detail': 'User Created'
                    })

                else:
                    return Response({
                        'status': False,
                        'detail': 'Failed to Load Otp'
                    })
        else:
            return Response({
                'status': False,
                'detail': 'Both Mobile No and Password Are Required'
            })
class Verify(APIView):
    def post(self, request, *args, **kwargs):
        phone = request.data.get('phone')
        password = request.data.get('password')
        otpv = request.data.get('otp')
        print(otpv)

        if phone and password and otpv:
            phone1 = str(phone)
            otpm = str(otpv)
            print(otpm)
            verify = PhoneOTP.objects.filter(phone__iexact=phone1).filter(otp__iexact=otpm)
            print(verify)
            if verify:
                return Response({
                    'status': True,
                    'detail': 'Logged in successfully'
                })
            else:
                return Response({
                    'status': False,
                    'detail': 'Incorrect Otp'
                })
        else:
            return Response({
                'status': False,
                'detail': ' Otp required'
            })
class UserViewSet(viewsets.ModelViewSet): #adding info of user
    queryset = UserInfo.objects.all()
    serializer_class = UserInfoSerializer
    @action(detail=True,methods=['POST'])

    def addInfo(self, request, pk):
        user = User.objects.get(id=pk)
        print(user.id)
        if 'name' and 'address' and 'gender'and'email' in request.data:
            name = request.data['name']
            address = request.data['address']
            gender = request.data['gender']
            mail = request.data['email']

            info = UserInfo.objects.create(user=user, name=name, address=address, gender=gender,email=mail)
            info.save()
            subject = 'welcome '
            message = f'Hi {info.name}, thank you for registering.'
            email_from = settings.EMAIL_HOST_USER
            recipient_list = [mail, ]
            send_mail(subject, message, email_from, recipient_list,fail_silently=False)

            serializer=UserInfoSerializer(info)
            response={'message':'Info Created','result':serializer.data}
            return Response(response,status=status.HTTP_200_OK)
        else:
            return Response({
                'status': False,
                'detail': 'All fields Are Necessary'
            })
class GroupList(ListAPIView):  #filter group on the basis of user

    serializer_class=GroupSerializer
    def get_queryset(self,*args,**kwargs):
        queryset_list=Group.objects.all()
        query=self.request.GET.get('q')
        if query:
            queryset_list=queryset_list.filter(
                Q(user=query)).distinct()
            print(queryset_list)
        return queryset_list
class GroupViewset(viewsets.ModelViewSet):#for adding new group
    queryset = Group.objects.all()
    serializer_class = GroupSerializer
    @action(detail=True, methods=['POST','GET'])
    def add_group(self,request,pk):
        user = User.objects.get(id=pk)

        if 'Groupname' in request.data:
            name=request.data['Groupname']
            print(name)
            group = Group.objects.create(user=user, Groupname=name)
            group.save()
            serializer = GroupSerializer(group)
            response = {'message': 'Info Created', 'result': serializer.data}
            return Response(response, status=status.HTTP_200_OK)
        else:
            return Response({
                'status': False,
                'detail': 'Both Mobile No and Password Are Required'
            })

    @action(detail=True, methods=['POST', 'GET'])
    def add_member(self,request,pk):
        group=Group.objects.get(id=pk)
        print(group)
        if 'member' and  'relation' in request.data:
            member = request.data['member']
            relation=request.data['relation']
            memberphone=str(member)
            if memberphone:
                user=User.objects.filter(phone__iexact=memberphone).first()
                print(user)

                if user:
                        userinfo=UserInfo.objects.get(user=user)
                        if userinfo:
                            member=Members.objects.create(group=group, member=userinfo,name=userinfo.name,relation=relation)
                            member.save()
                            serializer=MemberSerializer(member)
                            response = {'message': 'Member Added', 'result': serializer.data}
                            return Response(response, status=status.HTTP_200_OK)
                        else:
                            return Response({
                                'status': False,
                            '   detail': "Record Doesn't Exsist"
                            })

                else:
                        return Response({
                            'status': False,
                            'detail': 'User do not Exsists'


                        })

        else:
            return Response({
                'status': False,
                'detail': 'All fields are Necessary '
            })

class MemberList(ListAPIView):  #filter group on the basis of groupid

    serializer_class=MemberSerializer
    def get_queryset(self,*args,**kwargs):
        queryset_list=Members.objects.all()
        query=self.request.GET.get('q')
        if query:
            queryset_list=queryset_list.filter(
                Q(group=query)).distinct()
            print(queryset_list)
        return queryset_list



#class MemberViewset(APIView):

class ObtainAuthToken(APIView):
    throttle_classes = ()
    permission_classes = ()
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, parsers.JSONParser,)
    renderer_classes = (renderers.JSONRenderer,)
    serializer_class = AuthTokenSerializer

    if coreapi_schema.is_enabled():
        schema = ManualSchema(
            fields=[
                coreapi.Field(
                    name="phone",
                    required=True,
                    location='form',
                    schema=coreschema.String(
                        title="phone",
                        description="Valid phone for authentication",
                    ),
                ),
                coreapi.Field(
                    name="password",
                    required=True,
                    location='form',
                    schema=coreschema.String(
                        title="Password",
                        description="Valid password for authentication",
                    ),
                ),
            ],
            encoding="application/json",
        )

    def get_serializer_context(self):
        return {
            'request': self.request,
            'format': self.format_kwarg,
            'view': self
        }

    def get_serializer(self, *args, **kwargs):
        kwargs['context'] = self.get_serializer_context()
        return self.serializer_class(*args, **kwargs)

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        token, created = Token.objects.get_or_create(user=user)
        return Response({'token': token.key})
obtain_auth_token = ObtainAuthToken.as_view()
def send_otp(phone):
    if phone:
        otp = random.randint(999, 9999)
        return otp
    else:
        False

class MemberDetail(viewsets.ModelViewSet):
    queryset = Members.objects.all()
    serializer_class = MemberSerializer

    @action(detail=True, methods=[ 'GET'])
    def add_member(self, request, pk):
        member = Members.objects.get(id=pk)
        if member:
            serializer = MemberSerializer(member)
            response = {'message': 'member', 'result': serializer.data}
            return Response(response, status=status.HTTP_200_OK)
        else:
            return Response({
                'status': False,
                '   detail': "Record Doesn't Exsist"
            })







