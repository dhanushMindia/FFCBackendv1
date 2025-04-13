# services.py
import json
from tavily import TavilyClient
from groq import Groq
from django.conf import settings

# Initialize API clients
groq_client = Groq(api_key=settings.GROQ_API_KEY)
tavily_client = TavilyClient(api_key=settings.TAVILY_API_KEY)

def generate_search_query(questionnaire_data):
    """
    Generate a search query from questionnaire data
    
    Args:
        questionnaire_data: JSON data containing all questionnaire answers
    
    Returns:
        String containing the generated search query
    """

    formatted_data = json.dumps(questionnaire_data, indent=2)
    print(f"Formatted questionnaire data for Groq: {formatted_data[:500]}...")  # Show first 500 chars

    # Format the questionnaire data for the prompt
    prompt = f'''
    Below are responses from a user questionnaire about their innovation project or idea:

    {formatted_data}

    Create a natural language search query (maximum 400 characters) to find relevant active competitions available now 
    and in the next 6 months that match this project in India.

    Focus on:
    1. The core project concept and domain
    2. Project stage and team size
    3. Key technologies or approaches used

    The query should be in conversational English suitable for search engines - NOT in SQL or any query language.
    Include terms like "current", "active", "open", "upcoming", "2025","India" to find recent opportunities.

    Return ONLY the natural language search query without any explanations, SQL syntax, or additional content.
    '''
    
    # Call Groq API with the prompt
    chat_completion = groq_client.chat.completions.create(
        messages=[
            {
                "role": "user", 
                "content": prompt
            }
        ],
        model="meta-llama/llama-4-scout-17b-16e-instruct",
        temperature=1,
    )
    
    # Extract the generated query
    query = chat_completion.choices[0].message.content.strip()
    
    # Ensure query isn't too long
    if len(query) > 400:
        query = query[:397] + '...'
        
    return query

def search_competitions(query):
    """
    Use Tavily to search for relevant competitions and process results
    
    Args:
        query: Search query string
    
    Returns:
        Dictionary containing processed competition results
    """
    # Use the query directly without modification
    groq_query = query
    
    # Call Tavily API with the query
    search_result = tavily_client.search(
        query=groq_query,
        search_depth="advanced",
        max_results=10
    )
    
    print(f"Search query executed: {groq_query}")
    
    # Process each competition result
    competitions = []
    for idx, result in enumerate(search_result.get('results', [])):
        # Base score based on result position
        similarity_score = max(90 - (idx * 3), 70)
        
        # Get competition details
        title = result.get('title', 'Competition')
        url = result.get('url', '')
        content = result.get('content', '')
        
        # Generate summary using Groq
        summary = generate_content_summary(url, title, content)
        
        # Create competition object with only the needed fields
        competition = {
            'name': title,
            'similarity_score': similarity_score,
            'url': url,
            'summary': summary
        }
        
        competitions.append(competition)
    
    # Sort by similarity score (highest first)
    competitions.sort(key=lambda x: x['similarity_score'], reverse=True)
    
    # Return the processed results
    return {
        'competitions': competitions,
        'match_count': len(competitions)
    }

def calculate_similarity_score(result, questionnaire_data, index):
    """
    Calculate a similarity score between the competition and user's project
    
    Args:
        result: Tavily search result
        questionnaire_data: Dictionary of all questionnaire answers
        index: Position in search results (lower index = higher relevance)
        
    Returns:
        Integer score (0-100)
    """
    # Base score based on result position
    base_score = max(90 - (index * 3), 70)
    
    # Content-based adjustments
    content = result.get('content', '').lower()
    title = result.get('title', '').lower()
    combined_text = content + " " + title
    
    # Check for keyword matches
    match_bonus = 0
    
    # Try to find project domain/category match
    domain_keywords = []
    for field in ['category', 'problem', 'solution', 'interested_domain']:
        if field in questionnaire_data and questionnaire_data[field]:
            value = str(questionnaire_data[field]).lower()
            if isinstance(value, str) and len(value) > 3:
                domain_keywords.extend(value.split())
    
    # Count how many important keywords match
    matched_keywords = sum(1 for keyword in domain_keywords if len(keyword) > 3 and keyword in combined_text)
    
    if matched_keywords > 0:
        match_bonus = min(matched_keywords * 2, 10)  # Cap at 10 points
    
    # Final score (cap at 99)
    final_score = min(base_score + match_bonus, 99)
    return final_score

def generate_content_summary(competition_url, title, content):
    """
    Generate a concise summary of the competition using Groq
    
    Args:
        competition_url: URL of the competition
        title: Title of the competition
        content: Content excerpt from the Tavily search result
        
    Returns:
        Concise summary of the competition
    """
    prompt = f"""
    Please create a concise summary (60-80 words) of this competition based on the title and content excerpt:
    
    Title: {title}
    URL: {competition_url}
    Content excerpt: {content}
    
    Focus on describing:
    1. What the competition is about
    2. Who can apply
    3. Any key benefits or prizes
    
    Return ONLY the summary text without additional commentary.
    """
    
    # Call Groq API with the prompt
    chat_completion = groq_client.chat.completions.create(
        messages=[
            {
                "role": "user",
                "content": prompt
            }
        ],
        model="llama3-70b-8192",
        temperature=0.5,
        max_tokens=150
    )
    
    # Extract the generated summary
    summary = chat_completion.choices[0].message.content.strip()
    return summary