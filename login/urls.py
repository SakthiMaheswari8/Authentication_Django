from django.urls import path
from . import views
 
urlpatterns = [
    path('',views.home,name='home'),
    path('signup/',views.signup,name='signup'),
    path('login',views.login,name='login'),
    path('Refresh_token',views.Refresh_token, name='Refresh_token'),
    path('GetUserDetails',views.GetUserDetails,name='GetUserDetails'),
    path('GetUserDetails/<int:pk>',views.GetUserDetails,name='GetUserDetails')
]
