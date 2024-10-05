from rest_framework import status
from rest_framework import serializers
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.authtoken.models import Token
from django.contrib.auth import authenticate
from .serializers import StockImageUserSerializer,LoginSerializer,PasswordResetSerializer,SetNewPasswordSerializer
from rest_framework.permissions import AllowAny
from .models import StockImageUser
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes
from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.core.mail import EmailMessage
from django.conf import settings
from smtplib import SMTP
from django.urls import reverse
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from rest_framework.exceptions import ValidationError, AuthenticationFailed
from django.utils.encoding import force_str, force_bytes
from django.core.exceptions import ObjectDoesNotExist

class RegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        print("Register view reached")
        print("Request data:", request.data)
        serializer = StockImageUserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
           
            return Response({
                'user': StockImageUserSerializer(user).data,
                
            }, status=status.HTTP_201_CREATED)
        print("Serializer errors:", serializer.errors)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        print("Login view reached")
        print("Request data:", request.data)
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = authenticate(
                username=serializer.validated_data['username'],
                password=serializer.validated_data['password']
            )
            if user:
                token, created = Token.objects.get_or_create(user=user)
                return Response({
                    'user': StockImageUserSerializer(user).data,
                    'token': token.key
                })
        print("Authentication failed")
        return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
class ForgotPasswordView(APIView):
    serializer_class = PasswordResetSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        try:
            if serializer.is_valid(raise_exception=True):
                email = serializer.validated_data['email']
                user = StockImageUser.objects.get(email=email)
                
                # Generate token
                token = default_token_generator.make_token(user)
                uid = urlsafe_base64_encode(force_bytes(user.pk))
                
                # Create reset link
                reset_url = reverse('set-new-password')
                reset_link = f"{request.scheme}://{request.get_host()}{reset_url}?uidb64={uid}&token={token}"
                
                # Prepare email
                subject = "Password Reset Request"
                message = f"Use this link to reset your password: {reset_link}"
                
                # Send email using SMTP
                try:
                    with smtplib.SMTP(settings.EMAIL_HOST, settings.EMAIL_PORT) as server:
                        server.starttls()
                        server.login(settings.EMAIL_HOST_USER, settings.EMAIL_HOST_PASSWORD)
                        
                        msg = MIMEMultipart()
                        msg['From'] = settings.DEFAULT_FROM_EMAIL
                        msg['To'] = email
                        msg['Subject'] = subject
                        msg.attach(MIMEText(message, 'plain'))
                        
                        server.send_message(msg)
                
                    return Response({
                        'message': "A link has been sent to your email to reset your password"
                    }, status=status.HTTP_200_OK)
                except Exception as e:
                    print(f"Error sending email: {str(e)}")
                    return Response({
                        'message': "Failed to send password reset email"
                    }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except ValidationError as e:
            return Response({
                "message": "Email address is not registered"
            }, status=status.HTTP_400_BAD_REQUEST)
class SetNewPasswordView(APIView):
    serializer_class = SetNewPasswordSerializer

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            password = serializer.validated_data['password']
            confirm_password = serializer.validated_data['confirm_password']
            uidb64 = serializer.validated_data['uidb64']
            token = serializer.validated_data['token']

            if password != confirm_password:
                raise serializers.ValidationError("Passwords do not match")

            try:
                user_id = force_str(urlsafe_base64_decode(uidb64))
                user = StockImageUser.objects.get(pk=user_id)
            except (ValueError, ObjectDoesNotExist):
                raise AuthenticationFailed("Invalid reset link")

            if not default_token_generator.check_token(user, token):
                raise AuthenticationFailed("Reset link is invalid or has expired")

            user.set_password(password)
            user.save()

            return Response({'success': True, 'message': "Password reset successful"}, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)