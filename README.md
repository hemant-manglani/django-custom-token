# Django custom authentication

### This is the process how, I build this authentication system.
#
#
#### Step 1 : Create Django Project (In main python djngo must installed or use virtual environment)
```
django-admin startproject dj_auth
```

#### Step 2 : Install requirement in virtual environment
```
pip install -r requirements.txt
```

#### Step 3 : Create user app 

```
python manage.py startapp users
```

#### Step 4 : Add extra model and extra filed for user if you have. Add register & login views and urls. Add users api in django_auth.urls
#
#
# Main step to create authentication system
#
#### Step 5 : Create database tables.
```
python manage.py makemigrations
python manage.py migrate
```

#### Step 6 : Create superuser. (Enter username and password.)
```
python manage.py createsuperuser
```
```
python manage.py runserver
```

#### Step 7 : Register user : 
METHOD : POST
URL : http://127.0.0.1:8000/users/register/
Content-type: application/x-www-form-urlencoded
BODY: username, password, confirm_password, is_active

### Login
METHOD: POST
URL: http://127.0.0.1:8000/users/login/
Content-type: application/x-www-form-urlencoded
BODY: email and password (In my case)
