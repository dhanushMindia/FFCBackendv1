# questionnaire/admin.py
from django.contrib import admin
from .models import Question, QuestionnaireSubmission, Answer

@admin.register(Question)
class QuestionAdmin(admin.ModelAdmin):
    list_display = ('identifier', 'order', 'text', 'question_type', 'section', 'is_active', 'depends_on_question', 'depends_on_answer')
    list_filter = ('section', 'question_type', 'is_active')
    search_fields = ('text', 'identifier')
    ordering = ('order',)

@admin.register(QuestionnaireSubmission)
class QuestionnaireSubmissionAdmin(admin.ModelAdmin):
    list_display = ('user', 'is_complete', 'created_at', 'updated_at')
    list_filter = ('is_complete',)

@admin.register(Answer)
class AnswerAdmin(admin.ModelAdmin):
    list_display = ('submission', 'question', 'answer_value', 'answer_value', 'updated_at')
    list_filter = ('question__section',) # Filter by question section
    search_fields = ('answer_value', 'submission__user__email') # Search by user email