from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth import authenticate, get_user_model
from rest_framework_simplejwt.tokens import RefreshToken  # For JWT
from rest_framework.permissions import IsAuthenticated
from .serializers import UserRegistrationSerializer, UserLoginSerializer, UserDetailSerializer

#Google OAuth
from google.oauth2 import id_token
from google.auth.transport import requests


class UserRegistrationView(APIView):
    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {"success": True, "message": "User registered successfully"},
                status=status.HTTP_201_CREATED,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserLoginView(APIView):

    def post(self, request):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data.get("email")
            password = serializer.validated_data.get("password")
        else:
            email = request.data.get("email")  # Or just request.data['email']
            password = request.data.get("password")  # Or just request.data['password']

        user = authenticate(email=email, password=password)

        if user is not None:
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            refresh_token = str(refresh)

            return Response(
                {
                    "success": True,
                    "message": "Login successful",
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                },
                status=status.HTTP_200_OK,
            )
        else:
            return Response(
                {"success": False, "message": "Invalid credentials"},
                status=status.HTTP_401_UNAUTHORIZED,
            )

class GoogleLoginView(APIView):
    def post(self, request):
        token = request.data.get("idToken")

        try:
            # Verify the Google ID token using OAuth2 verification
            idinfo = id_token.verify_oauth2_token(token, requests.Request())

            # Ensure the token is issued by Google
            if idinfo.get('iss') not in ['accounts.google.com', 'https://accounts.google.com']:
                raise ValueError('Wrong issuer.')

            # Extract user information safely
            userid = idinfo.get('sub')  # Unique Google User ID
            email = idinfo.get('email')
            first_name = idinfo.get('given_name', '')  # ✅ Prevents KeyError
            last_name = idinfo.get('family_name', '')  # ✅ Prevents KeyError

            if not email:  # If email is missing, return an error
                return Response({"success": False, "message": "No email provided"}, status=status.HTTP_400_BAD_REQUEST)

            # Check if a user with this email already exists
            user = get_user_model().objects.filter(email=email).first()

            if user is None:
                # Create a new user if they don't exist
                user = get_user_model().objects.create_user(
                    email=email,
                    username=userid,  # Use Google User ID as username
                    first_name=first_name,
                    last_name=last_name,
                    password=None,  # No password for Google sign-in users
                )

            # Generate JWT tokens
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            refresh_token = str(refresh)

            return Response(
                {
                    "success": True,
                    "message": "Google Login successful",
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                },
                status=status.HTTP_200_OK,
            )

        except ValueError:
            return Response(
                {"success": False, "message": "Invalid Google credentials"},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        except Exception as e:
            return Response(
                {"success": False, "message": f"Internal Server Error: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

class UserDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        serializer = UserDetailSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)