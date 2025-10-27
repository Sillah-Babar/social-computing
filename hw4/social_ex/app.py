from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import collections
import json
import sqlite3
import hashlib
import re
from datetime import datetime
from flask import abort
# Global variables for ML models
_DETOXIFY_MODEL = None
_MODEL_INITIALIZED = False
import re

app = Flask(__name__)
app.secret_key = '123456789' 
DATABASE = 'database.sqlite'

# Load censorship data
# WARNING! The censorship.dat file contains disturbing language when decrypted. 
# If you want to test whether moderation works, 
# you can trigger censorship using these words: 
# tier1badword, tier2badword, tier3badword
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
    if 'db' not in g:
        g.db = sqlite3.connect(
            DATABASE,
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row

    return g.db


@app.teardown_appcontext
def close_connection(exception):
    """Closes the database again at the end of the request."""
    db = g.pop('db', None)

    if db is not None:
        db.close()


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

@app.template_filter('datetimeformat')
def datetimeformat(value):
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str):
        dt = datetime.strptime(value, '%Y-%m-%d %H:%M:%S')
    else:
        return "N/A"
    return dt.strftime('%b %d, %Y %H:%M')

REACTION_EMOJIS = {
    'like': '❤️', 'love': '😍', 'laugh': '😂',
    'wow': '😮', 'sad': '😢', 'angry': '😠',
}
REACTION_TYPES = list(REACTION_EMOJIS.keys())


@app.route('/')
def feed():
    #  1. Get Pagination and Filter Parameters 
    try:
        page = int(request.args.get('page', 1))
    except ValueError:
        page = 1
    sort = request.args.get('sort', 'new').lower()
    show = request.args.get('show', 'all').lower()
    
    # Define how many posts to show per page
    POSTS_PER_PAGE = 10
    offset = (page - 1) * POSTS_PER_PAGE

    current_user_id = session.get('user_id')
    params = []

    #  2. Build the Query 
    where_clause = ""
    if show == 'following' and current_user_id:
        where_clause = "WHERE p.user_id IN (SELECT followed_id FROM follows WHERE follower_id = ?)"
        params.append(current_user_id)

    # Add the pagination parameters to the query arguments
    pagination_params = (POSTS_PER_PAGE, offset)

    if sort == 'popular':
        query = f"""
            SELECT p.id, p.content, p.created_at, u.username, u.id as user_id,
                   IFNULL(r.total_reactions, 0) as total_reactions
            FROM posts p
            JOIN users u ON p.user_id = u.id
            LEFT JOIN (
                SELECT post_id, COUNT(*) as total_reactions FROM reactions GROUP BY post_id
            ) r ON p.id = r.post_id
            {where_clause}
            ORDER BY total_reactions DESC, p.created_at DESC
            LIMIT ? OFFSET ?
        """
        final_params = params + list(pagination_params)
        posts = query_db(query, final_params)
    elif sort == 'recommended':
        posts = recommend(current_user_id, False)
    else:  # Default sort is 'new'
        query = f"""
            SELECT p.id, p.content, p.created_at, u.username, u.id as user_id
            FROM posts p
            JOIN users u ON p.user_id = u.id
            {where_clause}
            ORDER BY p.created_at DESC
            LIMIT ? OFFSET ?
        """
        final_params = params + list(pagination_params)
        posts = query_db(query, final_params)

    posts_data = []
    for post in posts:
        # Determine if the current user follows the poster
        followed_poster = False
        if current_user_id and post['user_id'] != current_user_id:
            follow_check = query_db(
                'SELECT 1 FROM follows WHERE follower_id = ? AND followed_id = ?',
                (current_user_id, post['user_id']),
                one=True
            )
            if follow_check:
                followed_poster = True

        # Determine if the current user reacted to this post and with what reaction
        user_reaction = None
        if current_user_id:
            reaction_check = query_db(
                'SELECT reaction_type FROM reactions WHERE user_id = ? AND post_id = ?',
                (current_user_id, post['id']),
                one=True
            )
            if reaction_check:
                user_reaction = reaction_check['reaction_type']

        reactions = query_db('SELECT reaction_type, COUNT(*) as count FROM reactions WHERE post_id = ? GROUP BY reaction_type', (post['id'],))
        comments_raw = query_db('SELECT c.id, c.content, c.created_at, u.username, u.id as user_id FROM comments c JOIN users u ON c.user_id = u.id WHERE c.post_id = ? ORDER BY c.created_at ASC', (post['id'],))
        post_dict = dict(post)
        post_dict['content'], _ = moderate_content(post_dict['content'])
        comments_moderated = []
        for comment in comments_raw:
            comment_dict = dict(comment)
            comment_dict['content'], _ = moderate_content(comment_dict['content'])
            comments_moderated.append(comment_dict)
        posts_data.append({
            'post': post_dict,
            'reactions': reactions,
            'user_reaction': user_reaction,
            'followed_poster': followed_poster,
            'comments': comments_moderated
        })

    #  4. Render Template with Pagination Info 
    return render_template('feed.html.j2', 
                           posts=posts_data, 
                           current_sort=sort,
                           current_show=show,
                           page=page, # Pass current page number
                           per_page=POSTS_PER_PAGE, # Pass items per page
                           reaction_emojis=REACTION_EMOJIS,
                           reaction_types=REACTION_TYPES)

@app.route('/posts/new', methods=['POST'])
def add_post():
    """Handles creating a new post from the feed."""
    user_id = session.get('user_id')

    # Block access if user is not logged in
    if not user_id:
        flash('You must be logged in to create a post.', 'danger')
        return redirect(url_for('login'))

    # Get content from the submitted form
    content = request.form.get('content')

    # Pass the user's content through the moderation function
    moderated_content = content

    # Basic validation to ensure post is not empty
    if moderated_content and moderated_content.strip():
        db = get_db()
        db.execute('INSERT INTO posts (user_id, content) VALUES (?, ?)',
                   (user_id, moderated_content))
        db.commit()
        flash('Your post was successfully created!', 'success')
    else:
        # This will catch empty posts or posts that were fully censored
        flash('Post cannot be empty or was fully censored.', 'warning')

    # Redirect back to the main feed to see the new post
    return redirect(url_for('feed'))
    
    
@app.route('/posts/<int:post_id>/delete', methods=['POST'])
def delete_post(post_id):
    """Handles deleting a post."""
    user_id = session.get('user_id')

    # Block access if user is not logged in
    if not user_id:
        flash('You must be logged in to delete a post.', 'danger')
        return redirect(url_for('login'))

    # Find the post in the database
    post = query_db('SELECT id, user_id FROM posts WHERE id = ?', (post_id,), one=True)

    # Check if the post exists and if the current user is the owner
    if not post:
        flash('Post not found.', 'danger')
        return redirect(url_for('feed'))

    if post['user_id'] != user_id:
        # Security check: prevent users from deleting others' posts
        flash('You do not have permission to delete this post.', 'danger')
        return redirect(url_for('feed'))

    # If all checks pass, proceed with deletion
    db = get_db()
    # To maintain database integrity, delete associated records first
    db.execute('DELETE FROM comments WHERE post_id = ?', (post_id,))
    db.execute('DELETE FROM reactions WHERE post_id = ?', (post_id,))
    # Finally, delete the post itself
    db.execute('DELETE FROM posts WHERE id = ?', (post_id,))
    db.commit()

    flash('Your post was successfully deleted.', 'success')
    # Redirect back to the page the user came from, or the feed as a fallback
    return redirect(request.referrer or url_for('feed'))

@app.route('/u/<username>')
def user_profile(username):
    """Displays a user's profile page with moderated bio, posts, and latest comments."""
    
    user_raw = query_db('SELECT * FROM users WHERE username = ?', (username,), one=True)
    if not user_raw:
        abort(404)

    user = dict(user_raw)
    moderated_bio, _ = moderate_content(user.get('profile', ''))
    user['profile'] = moderated_bio

    posts_raw = query_db('SELECT id, content, user_id, created_at FROM posts WHERE user_id = ? ORDER BY created_at DESC', (user['id'],))
    posts = []
    for post_raw in posts_raw:
        post = dict(post_raw)
        moderated_post_content, _ = moderate_content(post['content'])
        post['content'] = moderated_post_content
        posts.append(post)

    comments_raw = query_db('SELECT id, content, user_id, post_id, created_at FROM comments WHERE user_id = ? ORDER BY created_at DESC LIMIT 100', (user['id'],))
    comments = []
    for comment_raw in comments_raw:
        comment = dict(comment_raw)
        moderated_comment_content, _ = moderate_content(comment['content'])
        comment['content'] = moderated_comment_content
        comments.append(comment)

    followers_count = query_db('SELECT COUNT(*) as cnt FROM follows WHERE followed_id = ?', (user['id'],), one=True)['cnt']
    following_count = query_db('SELECT COUNT(*) as cnt FROM follows WHERE follower_id = ?', (user['id'],), one=True)['cnt']

    #  NEW: CHECK FOLLOW STATUS 
    is_currently_following = False # Default to False
    current_user_id = session.get('user_id')
    
    # We only need to check if a user is logged in
    if current_user_id:
        follow_relation = query_db(
            'SELECT 1 FROM follows WHERE follower_id = ? AND followed_id = ?',
            (current_user_id, user['id']),
            one=True
        )
        if follow_relation:
            is_currently_following = True
    # --

    return render_template('user_profile.html.j2', 
                           user=user, 
                           posts=posts, 
                           comments=comments,
                           followers_count=followers_count, 
                           following_count=following_count,
                           is_following=is_currently_following)
    

@app.route('/u/<username>/followers')
def user_followers(username):
    user = query_db('SELECT * FROM users WHERE username = ?', (username,), one=True)
    if not user:
        abort(404)
    followers = query_db('''
        SELECT u.username
        FROM follows f
        JOIN users u ON f.follower_id = u.id
        WHERE f.followed_id = ?
    ''', (user['id'],))
    return render_template('user_list.html.j2', user=user, users=followers, title="Followers of")

@app.route('/u/<username>/following')
def user_following(username):
    user = query_db('SELECT * FROM users WHERE username = ?', (username,), one=True)
    if not user:
        abort(404)
    following = query_db('''
        SELECT u.username
        FROM follows f
        JOIN users u ON f.followed_id = u.id
        WHERE f.follower_id = ?
    ''', (user['id'],))
    return render_template('user_list.html.j2', user=user, users=following, title="Users followed by")

@app.route('/posts/<int:post_id>')
def post_detail(post_id):
    """Displays a single post and its comments, with content moderation applied."""
    
    post_raw = query_db('''
        SELECT p.id, p.content, p.created_at, u.username, u.id as user_id
        FROM posts p
        JOIN users u ON p.user_id = u.id
        WHERE p.id = ?
    ''', (post_id,), one=True)

    if not post_raw:
        # The abort function will stop the request and show a 404 Not Found page.
        abort(404)

    #  Moderation for the Main Post 
    # Convert the raw database row to a mutable dictionary
    post = dict(post_raw)
    # Unpack the tuple from moderate_content, we only need the moderated content string here
    moderated_post_content, _ = moderate_content(post['content'])
    post['content'] = moderated_post_content

    #  Fetch Reactions (No moderation needed) 
    reactions = query_db('''
        SELECT reaction_type, COUNT(*) as count
        FROM reactions
        WHERE post_id = ?
        GROUP BY reaction_type
    ''', (post_id,))

    #  Fetch and Moderate Comments 
    comments_raw = query_db('SELECT c.id, c.content, c.created_at, u.username, u.id as user_id FROM comments c JOIN users u ON c.user_id = u.id WHERE c.post_id = ? ORDER BY c.created_at ASC', (post_id,))
    
    comments = [] # Create a new list for the moderated comments
    for comment_raw in comments_raw:
        comment = dict(comment_raw) # Convert to a dictionary
        # Moderate the content of each comment
        print(comment['content'])
        moderated_comment_content, _ = moderate_content(comment['content'])
        comment['content'] = moderated_comment_content
        comments.append(comment)

    # Pass the moderated data to the template
    return render_template('post_detail.html.j2',
                           post=post,
                           reactions=reactions,
                           comments=comments,
                           reaction_emojis=REACTION_EMOJIS,
                           reaction_types=REACTION_TYPES)

@app.route('/about')
def about():
    return render_template('about.html.j2')

@app.route('/privacy')
def privacy():
    return render_template('privacy.html.j2')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        location = request.form.get('location', '')
        birthdate = request.form.get('birthdate', '')
        profile = request.form.get('profile', '')

        hashed_password = generate_password_hash(password)

        db = get_db()
        cur = db.cursor()
        try:
            cur.execute(
                'INSERT INTO users (username, password, location, birthdate, profile) VALUES (?, ?, ?, ?, ?)',
                (username, hashed_password, location, birthdate, profile)
            )
            db.commit()

            # 1. Get the ID of the user we just created.
            new_user_id = cur.lastrowid

            # 2. Add user info to the session cookie.
            session.clear() # Clear any old session data
            session['user_id'] = new_user_id
            session['username'] = username

            # 3. Flash a welcome message and redirect to the feed.
            flash(f'Welcome, {username}! Your account has been created.', 'success')
            return redirect(url_for('feed')) # Redirect to the main feed/dashboard

        except sqlite3.IntegrityError:
            flash('Username already taken. Please choose another one.', 'danger')
        finally:
            cur.close()
            db.close()
            
    return render_template('signup.html.j2')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        db.close()

        # 1. Check if the user exists.
        # 2. If user exists, use check_password_hash to securely compare the password.
        #    This function handles the salt and prevents timing attacks.
        if user and check_password_hash(user['password'], password):
            # Password is correct!
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash('Logged in successfully.', 'success')
            return redirect(url_for('feed'))
        else:
            # User does not exist or password was incorrect.
            flash('Invalid username or password.', 'danger')
            
    return render_template('login.html.j2')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/posts/<int:post_id>/comment', methods=['POST'])
def add_comment(post_id):
    """Handles adding a new comment to a specific post."""
    user_id = session.get('user_id')

    # Block access if user is not logged in
    if not user_id:
        flash('You must be logged in to comment.', 'danger')
        return redirect(url_for('login'))

    # Get content from the submitted form
    content = request.form.get('content')

    # Basic validation to ensure comment is not empty
    if content and content.strip():
        db = get_db()
        db.execute('INSERT INTO comments (post_id, user_id, content) VALUES (?, ?, ?)',
                   (post_id, user_id, content))
        db.commit()
        flash('Your comment was added.', 'success')
    else:
        flash('Comment cannot be empty.', 'warning')

    # Redirect back to the page the user came from (likely the post detail page)
    return redirect(request.referrer or url_for('post_detail', post_id=post_id))

@app.route('/comments/<int:comment_id>/delete', methods=['POST'])
def delete_comment(comment_id):
    """Handles deleting a comment."""
    user_id = session.get('user_id')

    # Block access if user is not logged in
    if not user_id:
        flash('You must be logged in to delete a comment.', 'danger')
        return redirect(url_for('login'))

    # Find the comment and the original post's author ID
    comment = query_db('''
        SELECT c.id, c.user_id, p.user_id as post_author_id
        FROM comments c
        JOIN posts p ON c.post_id = p.id
        WHERE c.id = ?
    ''', (comment_id,), one=True)

    # Check if the comment exists
    if not comment:
        flash('Comment not found.', 'danger')
        return redirect(request.referrer or url_for('feed'))

    # Security Check: Allow deletion if the user is the comment's author OR the post's author
    if user_id != comment['user_id'] and user_id != comment['post_author_id']:
        flash('You do not have permission to delete this comment.', 'danger')
        return redirect(request.referrer or url_for('feed'))

    # If all checks pass, proceed with deletion
    db = get_db()
    db.execute('DELETE FROM comments WHERE id = ?', (comment_id,))
    db.commit()

    flash('Comment successfully deleted.', 'success')
    # Redirect back to the page the user came from
    return redirect(request.referrer or url_for('feed'))

@app.route('/react', methods=['POST'])
def add_reaction():
    """Handles adding a new reaction or updating an existing one."""
    user_id = session.get('user_id')

    if not user_id:
        flash("You must be logged in to react.", "danger")
        return redirect(url_for('login'))

    post_id = request.form.get('post_id')
    new_reaction_type = request.form.get('reaction')

    if not post_id or not new_reaction_type:
        flash("Invalid reaction request.", "warning")
        return redirect(request.referrer or url_for('feed'))

    db = get_db()

    # Step 1: Check if a reaction from this user already exists on this post.
    existing_reaction = query_db('SELECT id FROM reactions WHERE post_id = ? AND user_id = ?',
                                 (post_id, user_id), one=True)

    if existing_reaction:
        # Step 2: If it exists, UPDATE the reaction_type.
        db.execute('UPDATE reactions SET reaction_type = ? WHERE id = ?',
                   (new_reaction_type, existing_reaction['id']))
    else:
        # Step 3: If it does not exist, INSERT a new reaction.
        db.execute('INSERT INTO reactions (post_id, user_id, reaction_type) VALUES (?, ?, ?)',
                   (post_id, user_id, new_reaction_type))

    db.commit()

    return redirect(request.referrer or url_for('feed'))

@app.route('/unreact', methods=['POST'])
def unreact():
    """Handles removing a user's reaction from a post."""
    user_id = session.get('user_id')

    if not user_id:
        flash("You must be logged in to unreact.", "danger")
        return redirect(url_for('login'))

    post_id = request.form.get('post_id')

    if not post_id:
        flash("Invalid unreact request.", "warning")
        return redirect(request.referrer or url_for('feed'))

    db = get_db()

    # Remove the reaction if it exists
    existing_reaction = query_db(
        'SELECT id FROM reactions WHERE post_id = ? AND user_id = ?',
        (post_id, user_id),
        one=True
    )

    if existing_reaction:
        db.execute('DELETE FROM reactions WHERE id = ?', (existing_reaction['id'],))
        db.commit()
        flash("Reaction removed.", "success")
    else:
        flash("No reaction to remove.", "info")

    return redirect(request.referrer or url_for('feed'))


@app.route('/u/<int:user_id>/follow', methods=['POST'])
def follow_user(user_id):
    """Handles the logic for the current user to follow another user."""
    follower_id = session.get('user_id')

    # Security: Ensure user is logged in
    if not follower_id:
        flash("You must be logged in to follow users.", "danger")
        return redirect(url_for('login'))

    # Security: Prevent users from following themselves
    if follower_id == user_id:
        flash("You cannot follow yourself.", "warning")
        return redirect(request.referrer or url_for('feed'))

    # Check if the user to be followed actually exists
    user_to_follow = query_db('SELECT id FROM users WHERE id = ?', (user_id,), one=True)
    if not user_to_follow:
        flash("The user you are trying to follow does not exist.", "danger")
        return redirect(request.referrer or url_for('feed'))
        
    db = get_db()
    try:
        # Insert the follow relationship. The PRIMARY KEY constraint will prevent duplicates if you've set one.
        db.execute('INSERT INTO follows (follower_id, followed_id) VALUES (?, ?)',
                   (follower_id, user_id))
        db.commit()
        username_to_follow = query_db('SELECT username FROM users WHERE id = ?', (user_id,), one=True)['username']
        flash(f"You are now following {username_to_follow}.", "success")
    except sqlite3.IntegrityError:
        flash("You are already following this user.", "info")

    return redirect(request.referrer or url_for('feed'))


@app.route('/u/<int:user_id>/unfollow', methods=['POST'])
def unfollow_user(user_id):
    """Handles the logic for the current user to unfollow another user."""
    follower_id = session.get('user_id')

    # Security: Ensure user is logged in
    if not follower_id:
        flash("You must be logged in to unfollow users.", "danger")
        return redirect(url_for('login'))

    db = get_db()
    cur = db.execute('DELETE FROM follows WHERE follower_id = ? AND followed_id = ?',
               (follower_id, user_id))
    db.commit()

    if cur.rowcount > 0:
        # cur.rowcount tells us if a row was actually deleted
        username_unfollowed = query_db('SELECT username FROM users WHERE id = ?', (user_id,), one=True)['username']
        flash(f"You have unfollowed {username_unfollowed}.", "success")
    else:
        # This case handles if someone tries to unfollow a user they weren't following
        flash("You were not following this user.", "info")

    # Redirect back to the page the user came from
    return redirect(request.referrer or url_for('feed'))

@app.route('/admin')
def admin_dashboard():
    """Displays the admin dashboard with users, posts, and comments, sorted by risk."""

    if session.get('username') != 'admin':
        flash("You do not have permission to access this page.", "danger")
        return redirect(url_for('feed'))

    RISK_LEVELS = { "HIGH": 5, "MEDIUM": 3, "LOW": 1 }
    PAGE_SIZE = 50

    def get_risk_profile(score):
        if score >= RISK_LEVELS["HIGH"]:
            return "HIGH", 3
        elif score >= RISK_LEVELS["MEDIUM"]:
            return "MEDIUM", 2
        elif score >= RISK_LEVELS["LOW"]:
            return "LOW", 1
        return "NONE", 0

    # Get pagination and current tab parameters
    try:
        users_page = int(request.args.get('users_page', 1))
        posts_page = int(request.args.get('posts_page', 1))
        comments_page = int(request.args.get('comments_page', 1))
    except ValueError:
        users_page = 1
        posts_page = 1
        comments_page = 1
    
    current_tab = request.args.get('tab', 'users') # Default to 'users' tab

    users_offset = (users_page - 1) * PAGE_SIZE
    
    # First, get all users to calculate risk, then apply pagination in Python
    # It's more complex to do this efficiently in SQL if risk calc is Python-side
    all_users_raw = query_db('SELECT id, username, profile, created_at FROM users')
    all_users = []
    for user in all_users_raw:
        user_dict = dict(user)
        user_risk_score = user_risk_analysis(user_dict['id'])
        risk_label, risk_sort_key = get_risk_profile(user_risk_score)
        user_dict['risk_label'] = risk_label
        user_dict['risk_sort_key'] = risk_sort_key
        user_dict['risk_score'] = min(5.0, round(user_risk_score, 2))
        all_users.append(user_dict)

    all_users.sort(key=lambda x: x['risk_score'], reverse=True)
    total_users = len(all_users)
    users = all_users[users_offset : users_offset + PAGE_SIZE]
    total_users_pages = (total_users + PAGE_SIZE - 1) // PAGE_SIZE

    # --- Posts Tab Data ---
    posts_offset = (posts_page - 1) * PAGE_SIZE
    total_posts_count = query_db('SELECT COUNT(*) as count FROM posts', one=True)['count']
    total_posts_pages = (total_posts_count + PAGE_SIZE - 1) // PAGE_SIZE

    posts_raw = query_db(f'''
        SELECT p.id, p.content, p.created_at, u.username, u.created_at as user_created_at
        FROM posts p JOIN users u ON p.user_id = u.id
        ORDER BY p.id DESC -- Order by ID for consistent pagination before risk sort
        LIMIT ? OFFSET ?
    ''', (PAGE_SIZE, posts_offset))
    posts = []
    for post in posts_raw:
        post_dict = dict(post)
        _, base_score = moderate_content(post_dict['content'])
        final_score = base_score 
        author_created_dt = post_dict['user_created_at']
        author_age_days = (datetime.utcnow() - author_created_dt).days
        if author_age_days < 7:
            final_score *= 1.5
        risk_label, risk_sort_key = get_risk_profile(final_score)
        post_dict['risk_label'] = risk_label
        post_dict['risk_sort_key'] = risk_sort_key
        post_dict['risk_score'] = round(final_score, 2)
        posts.append(post_dict)

    posts.sort(key=lambda x: x['risk_score'], reverse=True) # Sort after fetching and scoring

    # --- Comments Tab Data ---
    comments_offset = (comments_page - 1) * PAGE_SIZE
    total_comments_count = query_db('SELECT COUNT(*) as count FROM comments', one=True)['count']
    total_comments_pages = (total_comments_count + PAGE_SIZE - 1) // PAGE_SIZE

    comments_raw = query_db(f'''
        SELECT c.id, c.content, c.created_at, u.username, u.created_at as user_created_at
        FROM comments c JOIN users u ON c.user_id = u.id
        ORDER BY c.id DESC -- Order by ID for consistent pagination before risk sort
        LIMIT ? OFFSET ?
    ''', (PAGE_SIZE, comments_offset))
    comments = []
    for comment in comments_raw:
        comment_dict = dict(comment)
        _, score = moderate_content(comment_dict['content'])
        author_created_dt = comment_dict['user_created_at']
        author_age_days = (datetime.utcnow() - author_created_dt).days
        if author_age_days < 7:
            score *= 1.5
        risk_label, risk_sort_key = get_risk_profile(score)
        comment_dict['risk_label'] = risk_label
        comment_dict['risk_sort_key'] = risk_sort_key
        comment_dict['risk_score'] = round(score, 2)
        comments.append(comment_dict)

    comments.sort(key=lambda x: x['risk_score'], reverse=True) # Sort after fetching and scoring


    return render_template('admin.html.j2', 
                           users=users, 
                           posts=posts, 
                           comments=comments,
                           
                           # Pagination for Users
                           users_page=users_page,
                           total_users_pages=total_users_pages,
                           users_has_next=(users_page < total_users_pages),
                           users_has_prev=(users_page > 1),

                           # Pagination for Posts
                           posts_page=posts_page,
                           total_posts_pages=total_posts_pages,
                           posts_has_next=(posts_page < total_posts_pages),
                           posts_has_prev=(posts_page > 1),

                           # Pagination for Comments
                           comments_page=comments_page,
                           total_comments_pages=total_comments_pages,
                           comments_has_next=(comments_page < total_comments_pages),
                           comments_has_prev=(comments_page > 1),

                           current_tab=current_tab,
                           PAGE_SIZE=PAGE_SIZE)



@app.route('/admin/delete/user/<int:user_id>', methods=['POST'])
def admin_delete_user(user_id):
    if session.get('username') != 'admin':
        flash("You do not have permission to perform this action.", "danger")
        return redirect(url_for('feed'))
        
    if user_id == session.get('user_id'):
        flash('You cannot delete your own account from the admin panel.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    db = get_db()
    db.execute('DELETE FROM users WHERE id = ?', (user_id,))
    db.commit()
    flash(f'User {user_id} and all their content has been deleted.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/delete/post/<int:post_id>', methods=['POST'])
def admin_delete_post(post_id):
    if session.get('username') != 'admin':
        flash("You do not have permission to perform this action.", "danger")
        return redirect(url_for('feed'))

    db = get_db()
    db.execute('DELETE FROM comments WHERE post_id = ?', (post_id,))
    db.execute('DELETE FROM reactions WHERE post_id = ?', (post_id,))
    db.execute('DELETE FROM posts WHERE id = ?', (post_id,))
    db.commit()
    flash(f'Post {post_id} has been deleted.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/delete/comment/<int:comment_id>', methods=['POST'])
def admin_delete_comment(comment_id):
    if session.get('username') != 'admin':
        flash("You do not have permission to perform this action.", "danger")
        return redirect(url_for('feed'))

    db = get_db()
    db.execute('DELETE FROM comments WHERE id = ?', (comment_id,))
    db.commit()
    flash(f'Comment {comment_id} has been deleted.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/rules')
def rules():
    return render_template('rules.html.j2')

@app.template_global()
def loop_color(user_id):
    # Generate a pastel color based on user_id hash
    h = hashlib.md5(str(user_id).encode()).hexdigest()
    r = int(h[0:2], 16)
    g = int(h[2:4], 16)
    b = int(h[4:6], 16)
    return f'rgb({r % 128 + 80}, {g % 128 + 80}, {b % 128 + 80})'


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


    # is_flagged, confidence_score, label_probs = ml_content_check(text)

    # if is_flagged:
    #     if label_probs.get('obscene', 0) > 0.9:
    #         return "[content removed due to obscene content]", 5.0
    #     elif any(label_probs.get(label, 0) > 0.9 for label in ['threat', 'insult', 'identity_attack']):
    #         return "[content removed due to threatening/insulting content]", 5.0
    #     elif any(label_probs.get(label, 0) > 0.9 for label in ['severe_toxicity', 'toxicity']):
    #         return "[content removed due to severe toxicity]", 5.0
    #     elif confidence_score > 0.75:
    #         total_score += 3.5
    #     elif confidence_score > 0.6:
    #         total_score += 2.5

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

# Add after the other post-related routes (around line 450)

@app.route('/posts/<int:post_id>/report', methods=['POST'])
def report_post(post_id):
    """Handles reporting a post."""
    user_id = session.get('user_id')

    if not user_id:
        flash('You must be logged in to report posts.', 'danger')
        return redirect(url_for('login'))

    # Check if post exists
    post = query_db('SELECT id FROM posts WHERE id = ?', (post_id,), one=True)
    if not post:
        flash('Post not found.', 'danger')
        return redirect(url_for('feed'))

    # Check if user already reported this post
    existing_report = query_db(
        'SELECT id FROM reports WHERE post_id = ? AND reporter_id = ?',
        (post_id, user_id),
        one=True
    )
    
    if existing_report:
        flash('You have already reported this post.', 'info')
        return redirect(request.referrer or url_for('feed'))

    reason = request.form.get('reason')
    
    if not reason:
        flash('Please select a reason for reporting.', 'warning')
        return redirect(request.referrer or url_for('feed'))

    # Insert the report
    db = get_db()
    db.execute(
        'INSERT INTO reports (post_id, reporter_id, reason) VALUES (?, ?, ?)',
        (post_id, user_id, reason)
    )
    db.commit()

    flash('Thank you for your report. Our team will review it shortly.', 'success')
    return redirect(request.referrer or url_for('feed'))


@app.route('/admin/reports')
def admin_reports():
    """Displays reported posts for admin review."""
    if session.get('username') != 'admin':
        flash("You do not have permission to access this page.", "danger")
        return redirect(url_for('feed'))

    # Get all reports with post and reporter information
    reports = query_db('''
        SELECT r.id, r.reason, r.created_at,
               p.id as post_id, p.content as post_content,
               u.username as reporter_username,
               pu.username as post_author
        FROM reports r
        JOIN posts p ON r.post_id = p.id
        JOIN users u ON r.reporter_id = u.id
        JOIN users pu ON p.user_id = pu.id
        ORDER BY r.created_at DESC
    ''')

    # Group reports by post
    from collections import defaultdict
    reports_by_post = defaultdict(list)
    
    for report in reports:
        reports_by_post[report['post_id']].append(dict(report))

    return render_template('admin_reports.html.j2', reports_by_post=reports_by_post)

def user_risk_analysis(user_id):
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


if __name__ == '__main__':
    initialize_ml_model()
    app.run(debug=True, port=8080)

