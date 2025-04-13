# urls.py
from django.urls import path
from .views import GenerateQueryView, SearchCompetitionsView

app_name = 'results_processor'

urlpatterns = [
    # Generate and store a search query from questionnaire data
    path('generate-query/', GenerateQueryView.as_view(), name='generate-query'),
    
    # Search for competitions using stored query (GET) or provided query (POST)
    path('search/', SearchCompetitionsView.as_view(), name='search-competitions'),
]