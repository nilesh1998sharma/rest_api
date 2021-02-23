from django.urls import path
from rest_framework import routers
from django.urls import path,include
from .views import *
router=routers.DefaultRouter()
router.register('userinfo',UserViewSet)
router.register('group',GroupViewset)
router.register('member',MemberDetail)


urlpatterns = [
    path('',include(router.urls)),
    path('login', Login.as_view(), name='login'),
    path('verify', Verify.as_view(), name='verify'),
    path('grouplist',GroupList.as_view()),
    path('member_list', MemberList.as_view()),


]