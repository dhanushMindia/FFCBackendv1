# serializers.py - Updated
from rest_framework import serializers
from .models import UserQuery

class UserQuerySerializer(serializers.ModelSerializer):
    class Meta:
        model = UserQuery
        fields = ['id', 'query_text', 'created_at']

class CompetitionResultSerializer(serializers.Serializer):
    """Serializer for competition search results (not stored in DB)"""
    name = serializers.CharField()
    url = serializers.URLField()
    summary = serializers.CharField()
    similarity_score = serializers.IntegerField()

class SearchResponseSerializer(serializers.Serializer):
    """Serializer for the search response"""
    search_query = serializers.CharField()
    match_count = serializers.IntegerField()
    competitions = CompetitionResultSerializer(many=True)