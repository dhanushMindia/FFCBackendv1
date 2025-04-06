from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth import authenticate, get_user_model
from rest_framework_simplejwt.tokens import RefreshToken  # For JWT
from rest_framework.permissions import IsAuthenticated
from .serializers import UserRegistrationSerializer, UserLoginSerializer, UserDetailSerializer
import logging


#Google OAuth
from google.oauth2 import id_token
from google.auth.transport import requests

User = get_user_model()  # Get the active User model (our custom one)

class UserRegistrationView(APIView):
    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save() # serializer.save() now returns the created user
            # --- GENERATE AND RETURN TOKENS ---
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            refresh_token = str(refresh)
            return Response(
                {
                    "success": True,
                    "message": "User registered successfully",
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                },
                status=status.HTTP_201_CREATED, # Use 201 for resource creation
            )
        # Return validation errors if serializer is invalid
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class UserLoginView(APIView):
    def post(self, request):
        serializer = UserLoginSerializer(data=request.data)
        # Validate basic presence and format first
        if not serializer.is_valid():
             return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data.get("email")
        password = serializer.validated_data.get("password")

        # Attempt authentication using the custom user model's backend
        user = authenticate(request=request, email=email, password=password)

        if user is not None:
            # --- LOGIN SUCCESS ---
            refresh = RefreshToken.for_user(user)
            return Response(
                {
                    "success": True,
                    "message": "Login successful",
                    "access_token": str(refresh.access_token),
                    "refresh_token": str(refresh),
                },
                status=status.HTTP_200_OK,
            )
        else:
            # --- AUTHENTICATION FAILED: CHECK WHY ---
            try:
                # Check if a user with this email actually exists
                user_exists = User.objects.filter(email=email).exists()
                if user_exists:
                    # User exists, so the password must have been wrong
                    return Response(
                        {"success": False, "message": "Invalid credentials"},
                        status=status.HTTP_401_UNAUTHORIZED, # 401 for wrong credentials
                    )
                else:
                    # User with this email does not exist
                    return Response(
                        {"success": False, "error": "email_not_found", "message": "Email address not registered."},
                        status=status.HTTP_404_NOT_FOUND, # 404 is good for 'resource not found'
                    )
            except Exception as e:
                 # Log the error 'e' properly in a real app
                 print(f"Error during login existence check: {e}")
                 return Response(
                    {"success": False, "message": "An error occurred during login check."},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )

# ... (keep GoogleLoginView and UserDetailView) ...
# TODO: Review GoogleLoginView again to ensure username handling (userid) is still appropriate


logger = logging.getLogger(__name__) # Setup logger for the view

class GoogleLoginView(APIView):
    def post(self, request):
        token = request.data.get("idToken")

        # --- Suggestion 3: Check if token exists ---
        if not token:
            return Response(
                {"success": False, "message": "ID token not provided."},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            # Verify the Google ID token
            # Consider adding audience check: client_id = 'YOUR_GOOGLE_CLIENT_ID'
            # idinfo = id_token.verify_oauth2_token(token, requests.Request(), client_id)
            idinfo = id_token.verify_oauth2_token(token, requests.Request())

            # Issuer Check
            if idinfo.get('iss') not in ['accounts.google.com', 'https://accounts.google.com']:
                raise ValueError('Wrong issuer.')

            # Extract user information
            userid = idinfo.get('sub')
            email = idinfo.get('email')
            first_name = idinfo.get('given_name', '')
            last_name = idinfo.get('family_name', '')

            if not email:
                return Response({"success": False, "message": "No email provided in Google token"}, status=status.HTTP_400_BAD_REQUEST)
            if not userid:
                 return Response({"success": False, "message": "No user ID (sub) provided in Google token"}, status=status.HTTP_400_BAD_REQUEST)


            # --- Suggestion 1 & 2: Use get_or_create and update info ---
            user, created = User.objects.get_or_create(
                email=email,  # Lookup user by email
                defaults={    # Fields to use ONLY if creating a new user
                    'username': userid, # Use Google ID as username for new users
                    'first_name': first_name,
                    'last_name': last_name,
                    # 'password' is automatically set unusable by create_user via get_or_create
                }
            )

            if not created:
                # --- Suggestion 2: Update existing user's info ---
                # You might only want to update if the names are currently blank, or always update.
                update_fields = []
                if first_name and user.first_name != first_name:
                     user.first_name = first_name
                     update_fields.append('first_name')
                if last_name and user.last_name != last_name:
                     user.last_name = last_name
                     update_fields.append('last_name')

                if update_fields:
                    user.save(update_fields=update_fields)
                # No need to update username for existing user


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

        except ValueError as e:
            # Catches invalid token format, signature, issuer, expiry etc.
            logger.warning(f"Google token verification failed: {e}") # Log warning
            return Response(
                {"success": False, "message": f"Invalid Google credentials: {e}"},
                status=status.HTTP_401_UNAUTHORIZED,
            )
        except Exception as e:
            # --- Suggestion 4: Add Logging ---
            logger.error(f"Internal error during Google login for email {email if 'email' in locals() else 'unknown'}: {e}", exc_info=True)
            return Response(
                {"success": False, "message": f"An internal server error occurred."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class UserDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        serializer = UserDetailSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)