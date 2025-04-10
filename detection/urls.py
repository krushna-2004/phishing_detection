# from django.urls import path
# from . import views
# from django.contrib import admin

# urlpatterns = [
#     path('', views.homePage),
# ]
from django.urls import path
from . import views

urlpatterns = [
    path('', views.welcome, name='welcome'),
    path('scan/', views.scan, name='scan'),
    path('Learn More/', views.Info, name='Info'),
    path('Scan Email/', views.upload_email, name='Email'),
    path('Contact Us/', views.contact, name='contact'),
    path('about/', views.about, name='about'),
    path('support/', views.support, name='support'),
    path('signup/', views.signup, name='signup'),
    path('signin/', views.signin, name='signin'),
    # path("google-login/", views.google_login, name="google-login"),
    path("save_user/", views.save_user, name="save_user"),
    path("logout/", views.user_logout, name="logout"),
    path('login/', views.signin, name='login'), 
    path('scan_qr/', views.scan_qr, name='scan_qr'),     # renders the form
    path('scan_qr1/', views.scan_qr1, name='scan_qr1'),  # handles the image POST
]
