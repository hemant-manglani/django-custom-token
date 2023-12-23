from rest_framework import serializers
from users import models
from django.utils.translation import gettext_lazy as _


class MyAuthTokenSerializer(serializers.Serializer):
    email = serializers.EmailField(label=_("Email"))
    password = serializers.CharField(
        label=_("Password",),
        style={'input_type': 'password'},
        trim_whitespace=False
    )

    # def validate(self, attrs):
    #     email = attrs.get('email')
    #     password = attrs.get('password')
    #
    #     print("email ::", email)
    #     print("password ::", password)
    #
    #     if email and password:
    #         user_details = models.User.objects.filter(email=email)
    #         user = authenticate(request=self.context.get('request'),
    #                             username=user_details[0].username, password=password)
    #
    #         print("user ::", user)
    #         # The authenticate call simply returns None for is_active=False
    #         # users. (Assuming the default ModelBackend authentication
    #         # backend.)
    #         if not user:
    #             msg = _('Unable to log in with provided credentials.')
    #             raise serializers.ValidationError(msg, code='authorization')
    #     else:
    #         msg = _('Must include "email" and "password".')
    #         raise serializers.ValidationError(msg, code='authorization')
    #
    #     attrs['user'] = user
    #     return attrs


class RegisterSerializer(serializers.ModelSerializer):
    confirm_password = serializers.CharField()

    def validate(self, data):
        try:
            # user = models.User.objects.filter(username=data.get('username'))
            # if len(user) > 0:
            #     raise serializers.ValidationError(_("Username already exists"))
            email = models.User.objects.filter(email=data.get('email'))
            if len(email) > 0:
                raise serializers.ValidationError(_("Email already exists"))
        except models.User.DoesNotExist:
            pass

        if not data.get('password') or not data.get('confirm_password'):
            raise serializers.ValidationError(_("Empty Password"))

        if data.get('password') != data.get('confirm_password'):
            raise serializers.ValidationError(_("Mismatch"))

        return data

    class Meta:
        model = models.User
        fields = ('username', 'password', 'confirm_password', 'is_active', 'email')
        extra_kwargs = {'confirm_password': {'read_only': True}}

    def create(self, validated_data):
        user = models.User.objects.create(
            username=validated_data['username'],
            email=validated_data['email']
            # first_name=validated_data['first_name'],
            # last_name=validated_data['last_name']
        )

        user.set_password(validated_data['password'])
        user.save()

        return user