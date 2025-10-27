import sqlite3
import re
import numpy as np
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.decomposition import LatentDirichletAllocation

DB_PATH = 'database.sqlite'

def fetch_data():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('SELECT content FROM posts')
    posts = [r[0] for r in cur.fetchall()]
    cur.execute('SELECT content FROM comments')
    comments = [r[0] for r in cur.fetchall()]
    conn.close()
    return posts + comments

def clean_text(txt):
    if not txt:
        return ""
    txt = txt.lower()
    txt = re.sub(r'http\S+|www\S+|@\w+|#\w+', '', txt)
    txt = re.sub(r'[^a-z\s]', ' ', txt)
    return re.sub(r'\s+', ' ', txt).strip()

def stopwords():
    base = [
        'i','me','my','myself','we','our','ours','ourselves','you','your','yours',
        'he','him','his','she','her','hers','it','its','they','them','their',
        'the','and','a','an','in','of','on','to','for','by','is','was','are',
        'be','been','being','do','did','does','doing','so','too','very','not',
        'can','will','should','just','now','with','from','about','if','or','as',
        'at','this','that','these','those','then','than','but','because'
    ]
    extra = [
        'like','really','know','think','want','good','right','time','people',
        'today','well','also','would','could','should','maybe','probably','yeah',
        'yes','please','thanks','sorry','said','makes','make','made','lot','way',
        'thing','things','need','feel','felt','try','trying','got','getting'
    ]
    return list(set(base + extra))

def train_model(texts):
    vec = CountVectorizer(
        stop_words=stopwords(),
        max_features=2500,
        max_df=0.35,
        min_df=8,
        token_pattern=r'\b[a-z]{5,}\b',
        ngram_range=(1, 2)
    )
    mat = vec.fit_transform(texts)
    lda = LatentDirichletAllocation(
        n_components=25,
        random_state=42,
        max_iter=30,
        learning_method='online',
        batch_size=128,
        n_jobs=-1
    )
    lda.fit(mat)
    return lda, vec, mat, vec.get_feature_names_out()

def topic_score(words):
    avg_len = np.mean([len(w) for w in words])
    uniq = len(set(w[:4] for w in words)) / len(words)
    return uniq * 0.5 + min(1.0, avg_len / 8) * 0.5

def tag_topic(words):
    s = ' '.join(words).lower()
    tags = {
        "Travel": ['travel','trip','visit','city','country','airport','hotel'],
        "Food": ['food','cook','meal','recipe','restaurant','dinner'],
        "Health": ['health','fitness','wellness','therapy','exercise'],
        "Work": ['work','career','office','job','business'],
        "Politics": ['politics','government','policy','election'],
        "Entertainment": ['music','movie','film','show','concert'],
        "Sports": ['sport','team','player','match','game'],
        "Relationships": ['love','family','friend','relationship'],
        "Tech": ['tech','computer','software','digital','internet'],
        "Education": ['school','study','student','university'],
        "Books": ['book','reading','writing','author'],
        "Art": ['art','painting','creative','design'],
        "Fashion": ['fashion','style','clothes','outfit'],
        "Nature": ['nature','environment','animal','outdoor'],
        "Finance": ['money','finance','budget','investment'],
        "Home": ['home','house','living','apartment']
    }
    for name, kws in tags.items():
        if any(k in s for k in kws):
            return name
    return "General"

def jaccard(a, b):
    sa, sb = set(a[:7]), set(b[:7])
    return len(sa & sb) / len(sa | sb) if sa and sb else 0

def analyze_topics(lda, feat):
    results = []
    for i, comp in enumerate(lda.components_):
        idx = comp.argsort()[-10:][::-1]
        words = [feat[j] for j in idx]
        score = topic_score(words)
        label = tag_topic(words)
        results.append({"id": i, "words": words, "score": score, "label": label})
    results.sort(key=lambda x: x["score"], reverse=True)
    return results

def pick_unique(topics, n=10, th=0.3):
    chosen = []
    used = set()
    for t in topics:
        if len(chosen) >= n:
            break
        if t['label'] in used:
            continue
        if any(jaccard(t['words'], c['words']) > th for c in chosen):
            continue
        chosen.append(t)
        used.add(t['label'])
    return chosen

def show_results(selected):
    print("\n" + "="*80)
    print("TOP 10 DISTINCT TOPICS")
    print("="*80)
    for i, t in enumerate(selected, 1):
        print(f"\n#{i}. {t['label']} (Topic {t['id']+1}, Score: {t['score']:.3f})")
        print("-" * 80)
        for w in t['words']:
            print(f"  {w}")

def main():
    data = fetch_data()
    docs = [clean_text(d) for d in data if d and len(d) > 20]
    lda, vec, mat, feat = train_model(docs)
    all_t = analyze_topics(lda, feat)
    unique_t = pick_unique(all_t, 10)
    show_results(unique_t)

if __name__ == "__main__":
    main()
