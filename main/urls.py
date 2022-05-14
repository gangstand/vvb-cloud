from django.urls import path
from . import views
from .views import activate

urlpatterns = [
    path('', views.main, name='main'),
    path('register/', views.register, name='register'),
    path('login/', views.user_login, name='login'),
    path('logout/', views.user_logout, name='logout'),
    path('activate/<slug:uidb64>/<slug:token>/', activate, name='activate'),
    path('archive/', views.work_archive, name='archive'),
    path('archive/archive_del/<int:id>/', views.work_archive_del, name='archive_del'),
    path('encrypt/archive_del/<int:id>/', views.work_archive_del, name='archive_del'),
    path('decrypt/archive_del/<int:id>/', views.work_archive_del, name='archive_del'),
    path('checking/', views.work_checking, name='checking'),
    path('decrypt/', views.work_decrypt, name='decrypt'),
    path('encrypt/', views.work_encrypt, name='encrypt'),
    path('signature/', views.work_signature, name='signature'),
    path('cryptopro/', views.cryptopro, name='cryptopro'),
]