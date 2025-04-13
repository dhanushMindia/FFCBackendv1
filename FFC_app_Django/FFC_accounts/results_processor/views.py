# views.py
from django.db import transaction
from rest_framework import status, views
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .models import UserQuery
from .serializers import UserQuerySerializer, SearchResponseSerializer
from .services import generate_search_query, search_competitions, calculate_similarity_score, generate_content_summary

class GenerateQueryView(views.APIView):
    """
    Generate a search query from questionnaire data and store it for the user
    
    Expects a POST with questionnaire data in the request body.
    """
    permission_classes = [IsAuthenticated]
    
    @transaction.atomic
    def post(self, request, *args, **kwargs):
        user = request.user
        
        try:
            # Get questionnaire data from request body
            questionnaire_data = request.data
            
            if not questionnaire_data:
                return Response(
                    {"error": "No questionnaire data provided."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Generate search query from questionnaire data
            search_query = generate_search_query(questionnaire_data)
            
            # Save the search query
            user_query, created = UserQuery.objects.update_or_create(
                user=user,
                defaults={'query_text': search_query}
            )
            
            # Return success response
            return Response({
                "success": True,
                "message": "Search query generated and stored successfully.",
                "query": search_query
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            import traceback
            print(f"Error generating query: {str(e)}")
            print(traceback.format_exc())
            return Response(
                {"error": f"An error occurred during query generation: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class SearchCompetitionsView(views.APIView):
    """
    Search for competitions using the stored query or a provided query
    
    GET: Uses the user's stored query
    POST: Uses a query provided in the request body
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request, *args, **kwargs):
        user = request.user
        
        try:
            # Get the user's search query
            try:
                user_query = UserQuery.objects.get(user=user)
                query = user_query.query_text
            except UserQuery.DoesNotExist:
                return Response(
                    {"error": "No search query found. Please generate a query first."},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Search for competitions
            search_results = search_competitions(query)
            
            # Prepare response
            response_data = {
                "search_query": query,
            }
            
            return Response(response_data, status=status.HTTP_200_OK)
            
        except Exception as e:
            import traceback
            print(f"Error searching competitions: {str(e)}")
            print(traceback.format_exc())
            return Response(
                {"error": f"An error occurred during search: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def post(self, request, *args, **kwargs):
        try:
            # Get query from request body
            query = request.data.get('query')
            
            if not query:
                return Response(
                    {"error": "No search query provided."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Search for competitions
            search_results = search_competitions(query)
            
            # Prepare response
            response_data = {
                "search_query": query,
                "match_count": search_results['match_count'],
                "competitions": search_results['competitions']
            }
            
            return Response(response_data, status=status.HTTP_200_OK)
            
        except Exception as e:
            import traceback
            print(f"Error searching competitions: {str(e)}")
            print(traceback.format_exc())
            return Response(
                {"error": f"An error occurred during search: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )