import sqlite3
import pandas as pd
import numpy as np
from nltk.sentiment import SentimentIntensityAnalyzer
import nltk
from collections import defaultdict
import re

try:
    nltk.data.find('sentiment/vader_lexicon.zip')
except LookupError:
    nltk.download('vader_lexicon')

DB_FILE = 'database.sqlite'

TOPICS = {
    'General': ['seriously', 'before', 'believe', 'excitement', 'stuff', 'check', 'problem', 'misleading', 'jumping', 'considering'],
    'Relationships': ['great', 'difference', 'making', 'appreciate', 'energy', 'together', 'community', 'friend', 'positive', 'ignore'],
    'Art': ['sharing', 'beautiful', 'volunteering', 'reminder', 'tough', 'started', 'passion', 'weekend', 'shelter', 'years'],
    'Books': ['reading', 'amazing', 'simple', 'kindness', 'focus', 'perspective', 'someone', 'reminds', 'powerful', 'moment'],
    'Food': ['deeper', 'cooking', 'seems', 'others', 'feeling', 'frustrating', 'fresh', 'forget', 'considered', 'changer'],
    'Work': ['nothing', 'pretend', 'fascinating', 'learn', 'problems', 'progress', 'magical', 'special', 'works', 'solve'],
    'Sports': ['coffee', 'beauty', 'guess', 'personal', 'humor', 'challenges', 'sports', 'piece', 'captures', 'patience'],
    'Nature': ['might', 'nature', 'through', 'never', 'exploring', 'hidden', 'places', 'details', 'history', 'amazing'],
    'Entertainment': ['something', 'there', 'world', 'curious', 'missing', 'place', 'specific', 'enough', 'movie', 'vibes'],
    'Health': ['where', 'health', 'mental', 'mental health', 'journey', 'music', 'fashion', 'support', 'other', 'break']
}

def connect_db():
    return sqlite3.connect(DB_FILE)

def load_content():
    conn = connect_db()
    posts = pd.read_sql_query("SELECT id, content, user_id, created_at FROM posts", conn)
    comments = pd.read_sql_query("SELECT id, content, user_id, created_at FROM comments", conn)
    conn.close()
    return posts, comments

def clean_text(txt):
    if not txt:
        return ""
    txt = txt.lower()
    txt = re.sub(r'[^a-z\s]', '', txt)
    return re.sub(r'\s+', ' ', txt).strip()

def get_sentiment(txt):
    sia = SentimentIntensityAnalyzer()
    scores = sia.polarity_scores(txt)
    comp = scores['compound']
    if comp >= 0.05:
        cat = 'positive'
    elif comp <= -0.05:
        cat = 'negative'
    else:
        cat = 'neutral'
    return {'compound': comp, 'category': cat}

def match_topics(txt):
    clean = clean_text(txt)
    words = set(clean.split())
    matches = []
    for name, keys in TOPICS.items():
        hits = sum(1 for k in keys if k in clean or k in words)
        if hits > 0:
            matches.append((name, hits))
    matches.sort(key=lambda x: x[1], reverse=True)
    return [m[0] for m in matches] if matches else ['General']

def run_basic_analysis():
    posts, comments = load_content()
    post_scores = []
    for _, r in posts.iterrows():
        s = get_sentiment(r['content'])
        s['id'], s['type'] = r['id'], 'post'
        post_scores.append(s)
    comment_scores = []
    for _, r in comments.iterrows():
        s = get_sentiment(r['content'])
        s['id'], s['type'] = r['id'], 'comment'
        comment_scores.append(s)
    post_df = pd.DataFrame(post_scores)
    comment_df = pd.DataFrame(comment_scores)
    all_df = pd.concat([post_df, comment_df], ignore_index=True)
    return post_df, comment_df, all_df

def show_basic_stats(post_df, comment_df, all_df):
    print("\nOverall Sentiment Summary")
    print("-------------------------")
    print(f"Posts: {len(post_df)}, Comments: {len(comment_df)}, Total: {len(all_df)}")
    print(f"Positive: {(all_df['category']=='positive').sum()}  Neutral: {(all_df['category']=='neutral').sum()}  Negative: {(all_df['category']=='negative').sum()}")
    avg = all_df['compound'].mean()
    tone = "POSITIVE" if avg >= 0.05 else "NEGATIVE" if avg <= -0.05 else "NEUTRAL"
    print(f"Average sentiment score: {avg:+.4f}  →  Overall tone: {tone}")

def run_topic_analysis():
    conn = connect_db()
    posts = pd.read_sql_query("SELECT id, content FROM posts", conn)
    conn.close()
    topic_data = defaultdict(list)
    for _, r in posts.iterrows():
        s = get_sentiment(r['content'])
        for t in match_topics(r['content']):
            topic_data[t].append({'score': s['compound'], 'category': s['category']})
    results = []
    for t in sorted(TOPICS.keys()):
        if t not in topic_data:
            continue
        df = pd.DataFrame(topic_data[t])
        if len(df) == 0:
            continue
        stats = {
            'topic': t,
            'count': len(df),
            'avg': df['score'].mean(),
            'pos_pct': (df['category']=='positive').sum()/len(df)*100,
            'neu_pct': (df['category']=='neutral').sum()/len(df)*100,
            'neg_pct': (df['category']=='negative').sum()/len(df)*100
        }
        results.append(stats)
    return pd.DataFrame(results), topic_data

def compare_topics(df):
    if len(df) == 0:
        print("No topic data found.")
        return
    sorted_df = df.sort_values('avg', ascending=False)
    print("\nAverage Sentiment by Topic")
    print("--------------------------")
    for _, r in sorted_df.iterrows():
        tone = "POS" if r['avg'] >= 0.05 else "NEG" if r['avg'] <= -0.05 else "NEU"
        print(f"{r['topic']:<15} {r['avg']:+.3f} ({tone})")
    top = sorted_df.iloc[0]
    bottom = sorted_df.iloc[-1]
    print(f"\nMost positive: {top['topic']} ({top['avg']:+.3f})")
    print(f"Most negative: {bottom['topic']} ({bottom['avg']:+.3f})")

if __name__ == "__main__":
    post_df, comment_df, all_df = run_basic_analysis()
    show_basic_stats(post_df, comment_df, all_df)
    topic_df, topic_data = run_topic_analysis()
    compare_topics(topic_df)
    