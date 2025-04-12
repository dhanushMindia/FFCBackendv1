# questionnaire/urls.py
from django.urls import path
from .views import QuestionListView, SubmissionSaveView # Import the new views

app_name = 'questionnaire' # TODO: Add app namespace

urlpatterns = [
    # URL endpoint for Flutter to fetch the list of active questions
    path('questions/', QuestionListView.as_view(), name='question-list'),

    # URL endpoint for Flutter to POST the collected answers
    # This single endpoint handles saving/updating via the SubmissionSaveView's post method
    path('submission/', SubmissionSaveView.as_view(), name='submission-save-update'),

]