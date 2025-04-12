# questionnaire/views.py
from django.db import transaction
from rest_framework import status, generics, views
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated

from .models import Question, QuestionnaireSubmission, Answer
from .serializers import QuestionSerializer, AnswerWriteSerializer # Import necessary serializers

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


            # If loop completes, return overall success
            return Response(
                {"success": True, "message": "Answers processed.", "details": processed_results},
                status=status.HTTP_200_OK
            )

        except Exception as e:
            print(f"--- ERROR during submission processing: {e}")
            # Log error e properly
            return Response(
                {"error": "An internal error occurred while saving submission."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )