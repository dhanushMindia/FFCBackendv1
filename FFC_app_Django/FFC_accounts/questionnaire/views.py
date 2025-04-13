# questionnaire/views.py
from django.db import transaction
from rest_framework import status, generics, views
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated

from .models import Question, QuestionnaireSubmission, Answer
from .serializers import QuestionSerializer, AnswerWriteSerializer # Import necessary serializers

from django.urls import reverse
import requests
from django.conf import settings
import threading
import json  # Added import for JSON handling

# --- View to LIST Active Questions ---
class QuestionListView(generics.ListAPIView):
    """ API endpoint to fetch all active questionnaire questions """
    serializer_class = QuestionSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """ Return active questions, ordered by 'order' field """
        return Question.objects.filter(is_active=True).order_by('order')


# --- View to SAVE/UPDATE a user's submission ---
class SubmissionSaveView(views.APIView):
    """
    API endpoint for users to submit their questionnaire answers.
    Expects POST data like:
    {
        "answers": [
            {"question_identifier": "has_idea", "answer_value": "Yes"},
            {"question_identifier": "problem", "answer_value": "Solving X..."},
            {"question_identifier": "sdgs", "answer_value": ["Climate Action"]},
            {"question_identifier": "final_upload", "answer_value": null} // If file is skipped or handled separately
        ],
        "is_complete": true
    }
    Handles creating or updating the submission and answers.
    Does NOT handle direct file uploads in this version.
    """
    permission_classes = [IsAuthenticated]

    @transaction.atomic # Ensures the whole process succeeds or fails together
    def post(self, request, *args, **kwargs):
        user = request.user
        incoming_answers = request.data.get('answers', [])
        is_complete_flag = request.data.get('is_complete', True) # Default to complete

        if not isinstance(incoming_answers, list):
            return Response({"error": "'answers' must be a list."}, status=status.HTTP_400_BAD_REQUEST)

        print(f"Received submission attempt for user: {user.email}")

        try:
            # Get or create the overall submission record
            submission, created = QuestionnaireSubmission.objects.update_or_create(
                user=user,
                defaults={'is_complete': is_complete_flag}
            )
            print(f"Submission record {'created' if created else 'updated'}.")

            processed_results = []

            # Loop through each submitted answer
            for answer_data in incoming_answers:
                # Use the simple Write serializer for validation
                answer_serializer = AnswerWriteSerializer(data=answer_data)
                if answer_serializer.is_valid():
                    q_identifier = answer_serializer.validated_data['question_identifier']
                    a_value = answer_serializer.validated_data.get('answer_value') # JSONField content

                    try:
                        # Find the actual Question object
                        question_obj = Question.objects.get(identifier=q_identifier)

                        # Create or update the Answer linked to the submission and question
                        answer_obj, ans_created = Answer.objects.update_or_create(
                            submission=submission,
                            question=question_obj,
                            defaults={
                                'answer_value': a_value
                                # File handling would go here if processing uploads
                                # 'answer_file': ...
                            }
                        )
                        processed_results.append({
                            'question': q_identifier,
                            'status': 'saved' if ans_created else 'updated'
                        })
                        print(f"Processed answer for '{q_identifier}'")

                    except Question.DoesNotExist:
                        print(f"Error: Question '{q_identifier}' not found during answer save.")
                        processed_results.append({'question': q_identifier, 'status': 'error - question not found'})
                        # Optionally: Decide whether to fail the whole submission if one question is bad
                        # raise serializers.ValidationError(f"Question '{q_identifier}' not found.")

                else:
                    # Input data for this answer was invalid according to AnswerWriteSerializer
                    print(f"Invalid answer data received: {answer_data} - Errors: {answer_serializer.errors}")
                    processed_results.append({
                        'question': answer_data.get('question_identifier', 'unknown'),
                        'status': 'error - invalid input',
                        'errors': answer_serializer.errors
                    })
                    # Optionally: Fail the whole submission on first invalid answer
                    # return Response({"error": "Invalid answer data provided.", "details": answer_serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

            # Create the success response
            success_response = {
                "success": True, 
                "message": "Answers processed.", 
                "details": processed_results
            }
            
           # If submission is complete, trigger results processing
            if is_complete_flag:
                try:
                    # Get the API endpoint URL for results processing
                    process_url = request.build_absolute_uri(reverse('results_processor:process-results'))
                    
                    # Use the same authentication from the current request
                    headers = {
                        'Authorization': request.headers.get('Authorization'),
                        'Content-Type': 'application/json'
                    }
                    
                    # Define the function to run in a separate thread
                    def trigger_processing():
                        try:
                            # Make a POST request to the results processing endpoint
                            process_response = requests.post(process_url, headers=headers)
                            print(f"Results processing triggered. Status: {process_response.status_code}")
                            
                            # Optionally log any errors from the processing
                            if process_response.status_code >= 400:
                                print(f"Error in background results processing: {process_response.text}")
                        except Exception as e:
                            print(f"Exception in background results processing thread: {str(e)}")
                    
                    # Start processing in background thread so we don't delay the response
                    processing_thread = threading.Thread(target=trigger_processing)
                    processing_thread.daemon = True  # Thread will exit when main program exits
                    processing_thread.start()
                    
                    # Add info to response so client knows processing was started
                    success_response["results_processing"] = "initiated"
                    print("Results processing has been initiated in the background")
                    
                except Exception as e:
                    print(f"Error setting up results processing: {str(e)}")
                    # Don't fail the submission if results processing setup fails
                    success_response["results_processing"] = "error"
                    success_response["results_processing_error"] = str(e)

            # Replace with:

            # If submission is complete, trigger query generation
            if is_complete_flag:
                try:
                    # Get the API endpoint URL for query generation
                    generate_url = request.build_absolute_uri(reverse('results_processor:generate-query'))
                    
                    # Use the same authentication from the current request
                    headers = {
                        'Authorization': request.headers.get('Authorization'),
                        'Content-Type': 'application/json'
                    }
                    
                    # Extract valid questionnaire answers (filtering out null/empty answers)
                    formatted_questionnaire_data = {}
                    for answer in incoming_answers:
                        question_id = answer.get('question_identifier')
                        answer_value = answer.get('answer_value')
                        if question_id and answer_value:  # Only include non-empty answers
                            formatted_questionnaire_data[question_id] = answer_value
                    
                    # Define the function to run in a separate thread
                    def trigger_query_generation():
                        try:
                            # Make a POST request to the query generation endpoint with the questionnaire data
                            process_response = requests.post(
                                generate_url, 
                                headers=headers,
                                json=formatted_questionnaire_data  # Send only the valid answers
                            )
                            print(f"Query generation triggered. Status: {process_response.status_code}")
                            
                            # Optionally log any errors from the processing
                            if process_response.status_code >= 400:
                                print(f"Error in background query generation: {process_response.text}")
                            else:
                                print(f"Query generation response: {process_response.text}")
                        except Exception as e:
                            print(f"Exception in background query generation thread: {str(e)}")
                    
                    # Start processing in background thread so we don't delay the response
                    processing_thread = threading.Thread(target=trigger_query_generation)
                    processing_thread.daemon = True  # Thread will exit when main program exits
                    processing_thread.start()
                    
                    # Add info to response so client knows processing was started
                    success_response["query_generation"] = "initiated"
                    print("Query generation has been initiated in the background")
                    
                except Exception as e:
                    print(f"Error setting up query generation: {str(e)}")
                    # Don't fail the submission if query generation setup fails
                    success_response["query_generation"] = "error"
                    success_response["query_generation_error"] = str(e)
                        
            # Return the success response
            return Response(success_response, status=status.HTTP_200_OK)

        except Exception as e:
            print(f"--- ERROR during submission processing: {e}")
            # Log error e properly
            return Response(
                {"error": "An internal error occurred while saving submission."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        