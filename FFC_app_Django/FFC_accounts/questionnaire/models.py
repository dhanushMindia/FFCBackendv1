# questionnaire/models.py
from django.db import models
from django.conf import settings # To reference AUTH_USER_MODEL
from django.core.exceptions import ValidationError

# --- Question Model ---
class Question(models.Model):
    """ Defines a question in the questionnaire """

    # --- Updated choices based on your new types ---
    # Note: yesNo can be handled as singleSelect with ["Yes", "No"] options
    # Note: shortAnswer can be handled as descriptive
    # Note: multiSelect needs careful handling in Answer model/serializer
    QUESTION_TYPE_CHOICES = [
        ('singleSelect', 'Single Select Radio'), # For single choice from options
        ('multiSelect', 'Multiple Select Checkbox'), # For multiple choices from options
        ('descriptive', 'Short Answer / Descriptive Text'), # For text input
        ('fileUpload', 'File Upload'), # For file input
        ('yesNo', 'Yes/No Choice'), # Simplified single select
    ]

    identifier = models.SlugField( # Changed from id in your list to avoid conflict
        max_length=100, unique=True, primary_key=True, # Make identifier the primary key
        help_text="Unique identifier for this question (e.g., 'has_idea', 'problem')"
    )
    text = models.TextField(
        help_text="The wording of the question (questionText)"
    )
    question_type = models.CharField(
        max_length=20,
        choices=QUESTION_TYPE_CHOICES
    )
    section = models.CharField(
        max_length=100, blank=True, db_index=True,
        help_text="Section title for grouping (e.g., 'Your Idea & Current Stage')."
    )
    order = models.PositiveIntegerField(
        default=0, db_index=True,
        help_text="Order within the questionnaire/section."
    )
    is_active = models.BooleanField(
        default=True, db_index=True,
        help_text="Only active questions will be fetched."
    )

    # For singleSelect, multiSelect, yesNo
    # Store options as a JSON list of strings: ["Option A", "Option B"]
    options = models.JSONField(
        null=True, blank=True, default=list,
        help_text="JSON list of strings for choice options."
    )

    # For descriptive/shortAnswer
    hint_text = models.CharField(max_length=255, null=True, blank=True)
    max_characters = models.PositiveIntegerField(null=True, blank=True)

    # For Branching Logic (Condition)
    depends_on_question = models.ForeignKey(
        'self',
        on_delete=models.SET_NULL, # Keep question if parent deleted
        null=True, blank=True,
        related_name='dependent_questions',
        help_text="The 'key' (identifier) of the question this one depends on."
    )
    depends_on_answer = models.CharField(
        max_length=255, null=True, blank=True,
        help_text="The 'value' (answer text) from the parent question that triggers this one."
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['order', 'created_at']

    def clean(self):
        # Validation moved here or can be in Serializer too
        q_type = self.question_type
        is_choice = q_type in ['singleSelect', 'multiSelect', 'yesNo']
        if is_choice and not isinstance(self.options, list):
            raise ValidationError({'options': 'Options list is required for choice questions.'})
        if is_choice and len(self.options) < 1:
             raise ValidationError({'options': 'Must provide at least one option for choice questions.'})
        if q_type == 'yesNo' and self.options != ['Yes', 'No']:
             # Enforce Yes/No options if using dedicated type, or just use singleSelect
             # self.options = ['Yes', 'No'] # Option: Auto-set options
             raise ValidationError({'options': 'Options for yesNo type must be ["Yes", "No"]. Consider using singleSelect instead.'})
        if self.depends_on_answer and not self.depends_on_question:
             raise ValidationError({'depends_on_question': 'Cannot have depends_on_answer without depends_on_question.'})

    def __str__(self):
        return f"Q(id={self.identifier}, order={self.order}): {self.text[:50]}..."
    

# --- Questionnaire Submission Model ---
class QuestionnaireSubmission(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='questionnaire_submission',
        primary_key=True
    )
    is_complete = models.BooleanField(default=False, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
         return f"Submission for {getattr(self.user, self.user.USERNAME_FIELD)}"

#Answer model
class Answer(models.Model):
    submission = models.ForeignKey(
        QuestionnaireSubmission,
        on_delete=models.CASCADE,
        related_name='answers'
    )
    # Link identifier directly now since it's the PK of Question
    question = models.ForeignKey(
        Question,
        on_delete=models.PROTECT, # Or SET_NULL if question deletion is allowed
        related_name='answers'
    )
    # Use JSONField to store single string OR list of strings (for multiSelect)
    # Or keep TextField if you prefer storing multiSelect as comma-separated string
    answer_value = models.JSONField(null=True, blank=True, help_text="Stores text answer, single choice, or list of multi-choices.")

    answer_file = models.FileField(
        upload_to='user_answers/files/', # Consider user-specific subfolder: 'user_answers/{instance.submission.user_id}/'
        null=True, blank=True
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('submission', 'question') # Only one answer per question per submission
        ordering = ['question__order'] # Order answers by question order

    def __str__(self):
        answer_preview = str(self.answer_value) if self.answer_value else (str(self.answer_file) or "[No Value]")
        return f"Answer by {getattr(self.submission.user, self.submission.user.USERNAME_FIELD)} to Q '{self.question.identifier}': {answer_preview[:50]}"

    def clean(self):
        # Ensure only one answer type is provided
        if self.answer_value is not None and self.answer_file:
            raise ValidationError("Cannot provide both text/choice answer and file answer.")
        # Add more validation based on question_type if needed here or in serializer
        # e.g., ensure answer_value is in question.options for singleSelect