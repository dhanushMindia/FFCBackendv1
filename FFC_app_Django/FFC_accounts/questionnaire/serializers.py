# questionnaire/serializers.py
from rest_framework import serializers
from .models import Question, QuestionnaireSubmission, Answer
from django.conf import settings # To get User model if needed, though not directly here

# Serializer for sending Question data TO Flutter
# --- Serializer for Sending Question Data TO Flutter ---
class QuestionSerializer(serializers.ModelSerializer):
    # Get the identifier of the related question object for dependency check
    depends_on_question_identifier = serializers.SlugRelatedField(
        source='depends_on_question', # Source is the ForeignKey field on the Question model
        slug_field='identifier',    # We want the 'identifier' field of the related Question
        read_only=True              # This field is only for output
    )

    class Meta:
        model = Question
        # Fields needed by Flutter to render the question and handle logic
        fields = [
            'identifier',
            'text',
            'question_type',
            'section',
            'options', # JSONField list of strings
            'hint_text',
            'max_characters',
            'depends_on_question_identifier', # Send the parent identifier
            'depends_on_answer',
            'order', # Keep order if Flutter needs it
        ]



# --- Serializer for Reading/Displaying a SINGLE Answer ---
class AnswerSerializer(serializers.ModelSerializer):
    # Display the related question's identifier, not its DB ID
    question_identifier = serializers.SlugRelatedField(
        source='question',
        slug_field='identifier',
        read_only=True
    )

    class Meta:
        model = Answer
        fields = [
            'question_identifier',
            'answer_value', # The JSONField storing text or list
            'answer_file', # URL for the file if present
            'updated_at',
        ]




# --- Serializer for Reading/Displaying a User's FULL Submission ---
# This will be nested inside UserDetailSerializer later
class QuestionnaireSubmissionSerializer(serializers.ModelSerializer):
    # Nest related answers using AnswerSerializer
    answers = AnswerSerializer(many=True, read_only=True)
    # Optionally display user email or id
    # user_email = serializers.EmailField(source='user.email', read_only=True)

    class Meta:
        model = QuestionnaireSubmission
        fields = [
            'user_id', # Or user_email if defined above
            'is_complete',
            'created_at',
            'updated_at',
            'answers', # List of nested answer objects
            # Add other fields like 'raw_answers_json' if you included it
        ]

class AnswerWriteSerializer(serializers.Serializer): # Not a ModelSerializer
    question_identifier = serializers.SlugField(required=True)
    answer_value = serializers.JSONField(required=False, allow_null=True) # Allow null for skipped/file
    # answer_file would be handled separately if doing direct upload here

    def validate(self, data):
        # Check if question identifier exists
        try:
            Question.objects.get(identifier=data['question_identifier'])
        except Question.DoesNotExist:
            raise serializers.ValidationError({
                "question_identifier": f"Question with identifier '{data['question_identifier']}' not found."
            })
        # Add more validation? e.g., check answer_value format based on question_type?
        # Could be complex here, might be better handled in the view or model clean methods.
        return data
