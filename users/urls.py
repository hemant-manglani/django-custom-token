from django.urls import path, include, re_path
from users import views

urlpatterns = [
    path(r'users/login/', views.Login.as_view()),
    path(r'users/check/', views.Check.as_view()),
    path(r'users/register/', views.UserRegister.as_view(), name='register'),

]
