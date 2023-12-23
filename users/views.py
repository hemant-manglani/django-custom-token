from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
import json
from users import models, serializers
from django.db import transaction
from rest_framework.authtoken.models import Token
from rest_framework.authtoken import views as auth_views
from django.contrib.auth import authenticate
from .serializers import MyAuthTokenSerializer
from rest_framework.status import (
    HTTP_400_BAD_REQUEST,
    HTTP_404_NOT_FOUND,
    HTTP_200_OK,
)

from .authentication import token_expire_handler, expires_in


class Login(auth_views.ObtainAuthToken):
    permission_classes = (permissions.AllowAny,)

    def post(self, request, *args, **kwargs):
        # serializer_class = MyAuthTokenSerializer
        signin_serializer = MyAuthTokenSerializer(data=request.data)
        if not signin_serializer.is_valid():
            return Response(signin_serializer.errors, status=HTTP_400_BAD_REQUEST)

        email = signin_serializer.data['email']
        password = signin_serializer.data['password']
        user_details = models.User.objects.filter(email=email)
        user = authenticate(request=request,
                            username=user_details[0].username, password=password)

        if not user:
            return Response({'detail': 'Invalid Credentials or activate account'}, status=HTTP_404_NOT_FOUND)

        # TOKEN STUFF
        token, _ = Token.objects.get_or_create(user=user)

        # token_expire_handler will check, if the token is expired it will generate new one
        is_expired, token = token_expire_handler(token)  # The implementation will be described further

        return Response({
            'expires_in': expires_in(token),
            'token': token.key
        }, status=HTTP_200_OK)


# obtain_auth_token = MyAuthToken.as_view()


class UserRegister(APIView):
    permission_classes = (permissions.AllowAny,)

    def post(self, request):
        data = request.data
        data = data.dict()
        serializer = serializers.RegisterSerializer(data=data)
        if serializer.is_valid():
            try:
                with transaction.atomic():
                    serializer.save()
                    return Response(json.loads('{"message": "registration successful"}'), status=status.HTTP_200_OK)
            except Exception as e:
                return Response(data={"error": e.__str__()}, status=status.HTTP_400_BAD_REQUEST)
        return Response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class Check(APIView):
    permission_classes = (permissions.IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        return Response(json.loads('{"message": "Authenticated !"}'), status=status.HTTP_200_OK)
