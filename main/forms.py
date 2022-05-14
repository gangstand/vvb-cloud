from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User


class UserRegisterForm(UserCreationForm):
    username = forms.CharField(label='Имя пользователя', widget=forms.TextInput(
        attrs={'class': 'form-control', 'type': 'username', 'id': 'username', 'placeholder': 'Имя пользователя'}))
    email = forms.EmailField(label='Email', widget=forms.EmailInput(
        attrs={'class': 'form-control', 'type': 'username', 'id': 'username', 'placeholder': 'Почта'}))
    password1 = forms.CharField(label='Пароль', widget=forms.PasswordInput(
        attrs={'class': 'form-control', 'type': 'password', 'id': 'password', 'placeholder': 'Пароль'}))
    password2 = forms.CharField(label='Подтвержние пароля', widget=forms.PasswordInput(
        attrs={'class': 'form-control', 'type': 'password', 'id': 'password', 'placeholder': 'Подтверждение пароля'}))

    class Meta:
        model = User
        fields = ('username', 'email', 'password1', 'password2')


class UserLoginForm(AuthenticationForm):
    username = forms.CharField(label='Имя пользователя', widget=forms.TextInput(
        attrs={'class': 'form-control', 'type': 'username', 'id': 'username', 'placeholder': 'Имя пользователя'}))
    password = forms.CharField(label='Пароль', widget=forms.PasswordInput(
        attrs={'class': 'form-control', 'type': 'password', 'id': 'password', 'placeholder': 'Пароль'}))
