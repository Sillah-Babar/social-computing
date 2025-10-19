from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import collections
import json
import sqlite3
import hashlib
import re
from datetime import datetime
# Global variables for ML models
_DETOXIFY_MODEL = None
_MODEL_INITIALIZED = False
import re

DATABASE = '/Users/sillahbabar/Desktop/oulu/social/mini_social_exercise/database.sqlite'


ENCRYPTED_FILE_PATH = 'censorship.dat'
fernet = Fernet('xpplx11wZUibz0E8tV8Z9mf-wwggzSrc21uQ17Qq2gg=')
with open(ENCRYPTED_FILE_PATH, 'rb') as encrypted_file:
    encrypted_data = encrypted_file.read()
decrypted_data = fernet.decrypt(encrypted_data)
MODERATION_CONFIG = json.loads(decrypted_data)
TIER1_WORDS = MODERATION_CONFIG['categories']['tier1_severe_violations']['words']
TIER2_PHRASES = MODERATION_CONFIG['categories']['tier2_spam_scams']['phrases']
TIER3_WORDS = MODERATION_CONFIG['categories']['tier3_mild_profanity']['words']
print("Tier1: ", TIER1_WORDS)
print("TIER2_PHRASES: ", TIER2_PHRASES)
print("TIER3_WORDS: ", TIER3_WORDS)

def get_db():
    """
    Connect to the application's configured database. The connection
    is unique for each request and will be reused if this is called
    again.
    """
   
    db = sqlite3.connect(
        DATABASE,
        detect_types=sqlite3.PARSE_DECLTYPES
    )
    db.row_factory = sqlite3.Row

    return db

def query_db(query, args=(), one=False, commit=False):
    """
    Queries the database and returns a list of dictionaries, a single
    dictionary, or None. Also handles write operations.
    """
    db = get_db()
    
    # Using 'with' on a connection object implicitly handles transactions.
    # The 'with' statement will automatically commit if successful, 
    # or rollback if an exception occurs. This is safer.
    try:
        with db:
            cur = db.execute(query, args)
        
        # For SELECT statements, fetch the results after the transaction block
        if not commit:
            rv = cur.fetchall()
            return (rv[0] if rv else None) if one else rv
        
        # For write operations, we might want the cursor to get info like lastrowid
        return cur

    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return None
def initialize_ml_model():
    """
    Initialize pre-trained model for detecting inappropriate content.
    Uses Detoxify - a pre-trained model for toxic comment classification.
    """
    global _DETOXIFY_MODEL, _MODEL_INITIALIZED
    
    if _MODEL_INITIALIZED:
        return
    
    try:
        from detoxify import Detoxify
        # Load the model (downloads on first use, ~60MB)
        # Options: 'original', 'unbiased', 'multilingual'
        _DETOXIFY_MODEL = Detoxify('original')
        _MODEL_INITIALIZED = True
        print("Detoxify content classifier loaded successfully")
    except ImportError:
        print("Detoxify not installed. Install with: pip install detoxify")
        _MODEL_INITIALIZED = False
    except Exception as e:
        print(f"Error loading Detoxify model: {e}")
        _MODEL_INITIALIZED = False

def ml_content_check(text):
    """
    Uses pre-trained Detoxify model to detect inappropriate content.
    Returns (is_inappropriate: bool, confidence: float, categories: dict)
    """
    global _DETOXIFY_MODEL, _MODEL_INITIALIZED
    
    if not _MODEL_INITIALIZED:
        initialize_ml_model()
    
    if not _DETOXIFY_MODEL:
        return False, 0.0, {}
    
    try:
       
        results = _DETOXIFY_MODEL.predict(text)
        
        categories = {
            'toxicity': results['toxicity'],
            'severe_toxicity': results['severe_toxicity'],
            'obscene': results['obscene'],
            'threat': results['threat'],
            'insult': results['insult'],
            'identity_attack': results['identity_attack']
        }
        # print("categories: ", categories)
        # Determine if content is inappropriate based on thresholds
        is_severe = (
            categories['severe_toxicity'] > 0.7 or
            categories['threat'] > 0.7 or
            categories['toxicity'] > 0.75 or
            categories['obscene'] > 0.7 or
            categories['insult'] > 0.8
        )
        
        
        # Calculate overall confidence
        max_confidence = max(categories.values())
        # print("mac_conf: ", max_confidence)
        is_inappropriate = is_severe 
        # print("is_severe: ", is_severe)
        # print("is_inappropriate: ",  is_inappropriate)
        return is_inappropriate, max_confidence, categories
    except Exception as e:
        print(f"Error in ML content check: {e}")
        return False, 0.0, {}

def moderate_content(text):
    """
    Reviews user-submitted content for policy violations.
    Applies a tiered scoring system and auto-filters severe or inappropriate content.
    Includes checks for spam, personal info, toxic language, and ML-based moderation.
    """
    if not text:
        return "", 0

    cleaned_text = text
    total_score = 0
    text_lower = text.lower()


    words_in_text = re.findall(r'\b\w+\b', text_lower)
    for bad_word in TIER1_WORDS:
        if bad_word.lower() in words_in_text:
            return "[content removed due to severe violation]", 5.0

 
    for flagged_phrase in TIER2_PHRASES:
        if flagged_phrase.lower() in text_lower:
            return "[content removed due to spam/scam policy]", 5.0


    is_flagged, confidence_score, label_probs = ml_content_check(text)

    if is_flagged:
        if label_probs.get('obscene', 0) > 0.9:
            return "[content removed due to obscene content]", 5.0
        elif any(label_probs.get(label, 0) > 0.9 for label in ['threat', 'insult', 'identity_attack']):
            return "[content removed due to threatening/insulting content]", 5.0
        elif any(label_probs.get(label, 0) > 0.9 for label in ['severe_toxicity', 'toxicity']):
            return "[content removed due to severe toxicity]", 5.0
        elif confidence_score > 0.75:
            total_score += 3.5
        elif confidence_score > 0.6:
            total_score += 2.5

    for flagged_word in TIER3_WORDS:
        pattern = r'\b' + re.escape(flagged_word) + r'\b'
        matches = re.findall(pattern, cleaned_text, re.IGNORECASE)
        if matches:
            cleaned_text = re.sub(pattern, '*' * len(flagged_word), cleaned_text, flags=re.IGNORECASE)
            total_score += 2.0 * len(matches)

    link_pattern = r'https?://[^\s]+'
    links_found = re.findall(link_pattern, cleaned_text)
    if links_found:
        cleaned_text = re.sub(link_pattern, '[link removed]', cleaned_text)
        total_score += 2.0 * len(links_found)

    # Check for excessive capitalization
    letters_only = [char for char in cleaned_text if char.isalpha()]
    if len(letters_only) > 15:
        caps_count = sum(1 for char in letters_only if char.isupper())
        caps_ratio = caps_count / len(letters_only)
        if caps_ratio > 0.7:
            total_score += 0.5

    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
    if re.search(email_pattern, cleaned_text):
        cleaned_text = re.sub(email_pattern, '[email removed]', cleaned_text)
        total_score += 0.5


    phone_pattern = r'\b(?:\+?\d{1,3}[\s\-.]?)?\(?\d{2,4}\)?[\s\-.]?\d{2,4}[\s\-.]?\d{2,4}\b'
    if re.search(phone_pattern, cleaned_text):
        cleaned_text = re.sub(phone_pattern, '[phone removed]', cleaned_text)
        total_score += 0.5

    location_clues = [
        r'\b(my address is|i live at|call me at|meet me at|visit me at)\b',
        r'\b\d{1,5}\s+\w+\s+(street|st|avenue|ave|road|rd|boulevard|blvd|lane|ln|drive|dr)\b',
    ]
    for clue in location_clues:
        if re.search(clue, text_lower):
            cleaned_text = re.sub(clue, '[location info removed]', cleaned_text, flags=re.IGNORECASE)
            total_score += 0.5
            break

    return cleaned_text, total_score
def get_user_risk_score(user_id):
    """
    Checks how risky a user is by analyzing their profile and the stuff they post or comment.
    Gives a score up to 5.0
    """
    user = query_db('SELECT profile, created_at FROM users WHERE id = ?', (user_id,), one=True)
    if not user:
        return 0

    # Part 1: Profile
    profile = user['profile'] if user['profile'] else ""
    _, profile_score = moderate_content(profile)

    # Part 2: Posts
    user_posts = query_db('SELECT content FROM posts WHERE user_id = ?', (user_id,))
    if user_posts:
        post_scores = [moderate_content(p['content'])[1] for p in user_posts]
        moderated = [moderate_content(p['content'])[0] for p in user_posts]
        
        post_contents = [p['content'] for p in user_posts]
        # print("posts: ",post_contents)
        # print("moderated: ", moderated)
        # print("scores posts: ", post_scores)
        avg_post_score = sum(post_scores) / len(post_scores)
    else:
        avg_post_score = 0

    # Part 3: Comments
    user_comments = query_db('SELECT content FROM comments WHERE user_id = ?', (user_id,))
    if user_comments:
        comment_scores = [moderate_content(c['content'])[1] for c in user_comments]
        comments_all = [c['content'] for c in user_comments]
        # print("user comments: ",comments_all)
        # print("scores comments: ", comment_scores)
        avg_comment_score = sum(comment_scores) / len(comment_scores)
    else:
        avg_comment_score = 0

    # Final Score (weighted)
    total_score = (profile_score * 1) + (avg_post_score * 3) + (avg_comment_score * 1)

    # Account Age Effect
    acc_created = user['created_at']
    if isinstance(acc_created, str):
        acc_created = datetime.strptime(acc_created, '%Y-%m-%d %H:%M:%S')

    days_old = (datetime.utcnow() - acc_created).days

    if days_old < 7:
        total_score *= 1.5
    elif days_old < 30:
        total_score *= 1.2

    # Limit
    return min(5.0, total_score)


def behavior_check(user_id):
    """
    Looks at how the user behaves. Are they posting too much, spamming, or repeating stuff?
    Returns a multiplier (max 2.0) for their risk.
    """
    user = query_db('SELECT created_at FROM users WHERE id = ?', (user_id,), one=True)
    if not user:
        return 1.0

    multiplier = 1.0

   
    posts = query_db('SELECT created_at FROM posts WHERE user_id = ?', (user_id,))
    comments = query_db('SELECT created_at FROM comments WHERE user_id = ?', (user_id,))
    total = len(posts) + len(comments)

    created_at = user['created_at']
    if isinstance(created_at, str):
        created_at = datetime.strptime(created_at, '%Y-%m-%d %H:%M:%S')

    days_active = max(1, (datetime.utcnow() - created_at).days)
    rate = total / days_active

    if rate > 20:
        multiplier += 0.3
    elif rate > 10:
        multiplier += 0.15

    times = []
    for p in posts + comments:
        time = p['created_at']
        if isinstance(time, str):
            times.append(datetime.strptime(time, '%Y-%m-%d %H:%M:%S'))
        else:
            times.append(time)
    times.sort()

    fast_posts = 0
    for i in range(len(times) - 4):
        gap = (times[i + 4] - times[i]).total_seconds() / 60
        if gap < 10:
            fast_posts += 1

    if fast_posts > 3:
        multiplier += 0.25
    elif fast_posts > 0:
        multiplier += 0.1

    
    return min(2.0, multiplier)


def final_user_risk(user_id):
    """
    Combines basic risk with behavior risk to give the final risk score.
    """
    basic = get_user_risk_score(user_id)
    behavior = behavior_check(user_id)

    final = basic * behavior
    return min(5.0, final)

def recommend(user_id, filter_following):
    """
    Recommendation system that suggests posts based on:
    1. Posts the user reacted to positively (like, love, haha, wow)
    2. Users the user follows (if filter_following == True)
    Returns 5 relevant posts.
    """
    if not user_id:
        
        query = '''
            SELECT p.id, p.content, p.created_at, u.username, u.id as user_id
            FROM posts p
            JOIN users u ON p.user_id = u.id
            ORDER BY p.created_at DESC
            LIMIT 5
        '''
        return query_db(query)
    
    liked_posts = query_db('''
        SELECT DISTINCT post_id 
        FROM reactions 
        WHERE user_id = ? 
          AND reaction_type IN ('like', 'love', 'haha', 'wow')
    ''', (user_id,))
    liked_post_ids = [row['post_id'] for row in liked_posts]

    # Get followed users
    followed_users = query_db('''
        SELECT followed_id 
        FROM follows 
        WHERE follower_id = ?
    ''', (user_id,))
    followed_ids = [row['followed_id'] for row in followed_users]

    interacted = query_db('''
        SELECT DISTINCT post_id 
        FROM reactions 
        WHERE user_id = ?
    ''', (user_id,))
    interacted_ids = [row['post_id'] for row in interacted]

   
    if filter_following and followed_ids:
        placeholders = ','.join('?' * len(followed_ids))
        filter_clause = f"p.user_id IN ({placeholders})"
        params = followed_ids

        if interacted_ids:
            seen_placeholders = ','.join('?' * len(interacted_ids))
            filter_clause += f" AND p.id NOT IN ({seen_placeholders})"
            params += interacted_ids

        query = f'''
            SELECT p.id, p.content, p.created_at, u.username, u.id as user_id
            FROM posts p
            JOIN users u ON p.user_id = u.id
            WHERE {filter_clause}
            ORDER BY p.created_at DESC
            LIMIT 5
        '''
        results = query_db(query, params)
        if results:
            return results

    if liked_post_ids:
        placeholders = ','.join('?' * len(liked_post_ids))
        similar_users = query_db(f'''
            SELECT user_id
            FROM reactions
            WHERE post_id IN ({placeholders})
              AND user_id != ?
              AND reaction_type IN ('like', 'love', 'haha', 'wow')
            GROUP BY user_id
            ORDER BY COUNT(*) DESC
            LIMIT 10
        ''', liked_post_ids + [user_id])
        similar_user_ids = [row['user_id'] for row in similar_users]

        if similar_user_ids:
            sim_placeholders = ','.join('?' * len(similar_user_ids))
            params = similar_user_ids

            where_clause = "r.user_id IN (" + sim_placeholders + ")"
            
            if interacted_ids:
                seen_placeholders = ','.join('?' * len(interacted_ids))
                where_clause += f" AND p.id NOT IN ({seen_placeholders})"
                params += interacted_ids

            if filter_following and followed_ids:
                follow_placeholders = ','.join('?' * len(followed_ids))
                where_clause += f" AND p.user_id IN ({follow_placeholders})"
                params += followed_ids

            query = f'''
                SELECT p.id, p.content, p.created_at, u.username, u.id as user_id,
                       COUNT(*) as recommendation_score
                FROM posts p
                JOIN users u ON p.user_id = u.id
                JOIN reactions r ON p.id = r.post_id
                WHERE {where_clause}
                  AND r.reaction_type IN ('like', 'love', 'haha', 'wow')
                GROUP BY p.id
                ORDER BY recommendation_score DESC, p.created_at DESC
                LIMIT 5
            '''
            results = query_db(query, params)
            if results:
                return results

    params = []
    where_clauses = []

    if interacted_ids:
        placeholders = ','.join('?' * len(interacted_ids))
        where_clauses.append(f"p.id NOT IN ({placeholders})")
        params += interacted_ids

    if filter_following and followed_ids:
        placeholders = ','.join('?' * len(followed_ids))
        where_clauses.append(f"p.user_id IN ({placeholders})")
        params += followed_ids

    where_clause = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""

    fallback_query = f'''
        SELECT p.id, p.content, p.created_at, u.username, u.id as user_id,
               IFNULL(r.reaction_count, 0) as recommendation_score
        FROM posts p
        JOIN users u ON p.user_id = u.id
        LEFT JOIN (
            SELECT post_id, COUNT(*) as reaction_count 
            FROM reactions 
            WHERE reaction_type IN ('like', 'love', 'haha', 'wow')
            GROUP BY post_id
        ) r ON p.id = r.post_id
        {where_clause}
        ORDER BY recommendation_score DESC, p.created_at DESC
        LIMIT 5
    '''
    return query_db(fallback_query, params)


# Find top 5 highest risk users using base analysis


all_users = query_db('SELECT id, username FROM users')
user_risks = []

for user in all_users:
    risk_score = get_user_risk_score(user['id'])
    user_risks.append({
        'user_id': user['id'],
        'username': user['username'],
        'risk_score': risk_score
    })

user_risks.sort(key=lambda x: x['risk_score'], reverse=True)

print("TOP 5 HIGHEST RISK USERS (Enhanced Analysis with Behavioral Patterns)")

enhanced_risks = []
for user in all_users:
    base_risk = get_user_risk_score(user['id'])
    behavioral_mult = behavior_check(user['id'])
    enhanced_score = final_user_risk(user['id'])
    
    enhanced_risks.append({
        'user_id': user['id'],
        'username': user['username'],
        'base_risk': base_risk,
        'behavioral_multiplier': behavioral_mult,
        'enhanced_score': enhanced_score
    })
    print("enhanced_risk: ", {
        'user_id': user['id'],
        'username': user['username'],
        'base_risk': base_risk,
        'behavioral_multiplier': behavioral_mult,
        'enhanced_score': enhanced_score
    })

enhanced_risks.sort(key=lambda x: x['enhanced_score'], reverse=True)

for i, user in enumerate(enhanced_risks[:5], 1):
    print(f"{i}. User ID: {user['user_id']}, Username: {user['username']}")
    print(f"   Base Risk: {user['base_risk']:.3f} | Behavioral Multiplier: {user['behavioral_multiplier']:.2f} | Enhanced Score: {user['enhanced_score']:.3f}")

print("User 11: Following True")
results = recommend(11, True)
for row in results:
    print(f"Post ID: {row['id']}, Content: {row['content']}")


print("User 11: Following False")
results = recommend(11, False)
for row in results:
    print(f"Post ID: {row['id']}, Content: {row['content']}")

print("User 13: Following True")

results = recommend(13, True)
for row in results:
    print(f"Post ID: {row['id']}, Content: {row['content']}")


print("User 13: Following False")
results = recommend(13, False)
for row in results:
    print(f"Post ID: {row['id']}, Content: {row['content']}")

