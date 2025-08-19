from django.urls import path
from . import views
 
urlpatterns = [
    path('',views.home,name='home'),
    path('signup/',views.signup,name='signup'),
    path('login',views.login,name='login'),
    path('validate_token',views.validate_token, name='validate_token'),
    path('GetUserDetails',views.GetUserDetails,name='GetUserDetails'),
    path('GetUserDetails/<int:pk>',views.GetUserDetails,name='GetUserDetails'),

]
