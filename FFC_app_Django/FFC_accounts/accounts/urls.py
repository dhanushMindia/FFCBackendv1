from django.urls import path
from .views import UserRegistrationView, UserLoginView, UserDetailView,GoogleLoginView
from django.views.decorators.http import require_http_methods

urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name='user-registration'),
    path('login/', UserLoginView.as_view(), name='user-login'),
    path('me/', UserDetailView.as_view(), name='user-detail'),
    path('login/google/', GoogleLoginView.as_view(), name='user-login-google'),
]
