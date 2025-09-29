import sqlite3
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from datetime import datetime, timedelta
from sklearn.linear_model import LinearRegression
from collections import defaultdict


print("######################### Task 2.1 ##################################")
conn = sqlite3.connect('database.sqlite')
cursor = conn.cursor()

query = """
SELECT 
    DATE(created_at) as user_created,
    COUNT(*) as num_users
FROM users 
GROUP BY DATE(created_at)
ORDER BY user_created
"""

df = pd.read_sql_query(query, conn)
# conn.close()

# Convert to datetime and calculate cumulative users
df['user_created'] = pd.to_datetime(df['user_created'])
df['cusers'] = df['num_users'].cumsum()

# Add days since start for regression
earliest_date = df['user_created'].min()
print("max_date: ", df['user_created'].max())
df['days_s'] = (df['user_created'] - earliest_date).dt.days


X = df['days_s'].values.reshape(-1, 1)
y = df['cusers'].values

model = LinearRegression()
model.fit(X, y)

current_date = df['user_created'].max()
current_users = df['cusers'].iloc[-1]
current_servers = 16

users_p_server = current_users / current_servers

print(f"users: {current_users}")
print(f"servers: {current_servers}")
print(f"Users/server: {users_p_server}")

days_in_3_years = 3 * 365
future_days = df['days_s'].iloc[-1] + days_in_3_years
predicted_users_3_years = model.predict([[future_days]])[0]

print(f"Prediction:") 
print(f"Daily growth rate: {model.coef_[0]} users/day")
print(f"Predicted users in 3 years: {predicted_users_3_years}")

# Calculate servers needed
servers_req = predicted_users_3_years / users_p_server
servers_req_w_20_percent_redundancy = servers_req * 1.2  # 20% redundancy

print(f"Servers Needed")
print(f"servers needed in 3 years: {servers_req}")
print(f"With 20 percent redundancy: {servers_req_w_20_percent_redundancy}")
print(f"Total servers to rent: {int(np.ceil(servers_req_w_20_percent_redundancy))}")

# Create visualization
fig, ax1 = plt.subplots(1, 1, figsize=(12, 12))

# Plot 1: Historical user growth
ax1.plot(df['user_created'], df['cusers'], label='Actual Users')

# Add prediction line
future_date = current_date + timedelta(days=days_in_3_years)
prediction_x = [current_date, future_date]
prediction_y = [current_users, predicted_users_3_years]
ax1.plot(prediction_x, prediction_y, 'r--', label='Three Year Projection')

ax1.set_title('User Growth Trend', fontsize=13, fontweight='bold')
ax1.set_xlabel('Date')
ax1.set_ylabel('Cumulative Users')
ax1.legend()
ax1.grid(True, alpha=0.9)


plt.tight_layout()
plt.show()

print("######################### Task 2.2 ##################################")
cursor.execute("""
    SELECT 
    p.user_id,
    p.content,
    u.username,
    COUNT(DISTINCT r.id) as reaction_c,
    COUNT(DISTINCT c.id) as comment_c,
    (COUNT(DISTINCT r.id) * 1.0 + COUNT(DISTINCT c.id) * 1.5) as score
    FROM posts p
    JOIN users u ON p.user_id = u.id
    LEFT JOIN reactions r ON p.id = r.post_id
    LEFT JOIN comments c ON p.id = c.post_id
    GROUP BY p.user_id, p.content, u.username
    ORDER BY score DESC
    LIMIT 3
""")

top_posts = cursor.fetchall()
index = 0
for index, post in enumerate(top_posts, start=1):
    print("-------------------------")
    print(f"Virality: {index}")
    print(f"Content: {post[1]}")
    print(f"Username: {post[2]}")
    print(f"reaction_c: {post[3]}")
    print(f"comment_c: {post[4]}")
    print(f"score: {post[5]}")
    print("-------------------------")
    index+=1

print("######################### Task 2.3 ##################################")
engagement_query = """
WITH max_min_comments_times AS (
    SELECT
        post_id,
        MIN(created_at) AS earliest_engagement,
        MAX(created_at) AS end_engagement
    FROM comments
    GROUP BY post_id
),
time_deltas AS (
    SELECT
        JULIANDAY(c.earliest_engagement) - JULIANDAY(p.created_at) AS time_earliest_engagement,
        JULIANDAY(c.end_engagement) - JULIANDAY(p.created_at) AS time_lastest_engagement
    FROM posts p
    JOIN max_min_comments_times c ON p.id = c.post_id
)
SELECT
    ROUND(AVG(time_earliest_engagement * 24), 2) AS avg_hrs_first_engagement,
    ROUND(AVG(time_lastest_engagement * 24), 2) AS avg_hrs_last_engagement
FROM time_deltas;
"""

cursor.execute(engagement_query)
results = cursor.fetchall()

print(f"avg first engagement: {results[0][0]}")
print(f"avg last engagement: {results[0][1]}")

print("######################### Task 2.4 ##################################")
engagement_query = """
WITH interactions AS (
    SELECT 
        r.user_id as engager_id,
        p.user_id as author_id,
        COUNT(*) as it_count
    FROM reactions r
    JOIN posts p ON r.post_id = p.id
    WHERE r.user_id != p.user_id
    GROUP BY r.user_id, p.user_id
    
    UNION ALL
    
    SELECT 
        c.user_id as engager_id,
        p.user_id as author_id,
        COUNT(*) as it_count
    FROM comments c
    JOIN posts p ON c.post_id = p.id
    WHERE c.user_id != p.user_id
    GROUP BY c.user_id, p.user_id
)


    SELECT 
        engager_id,
        author_id,
        SUM(it_count) as total_it
    FROM interactions
    GROUP BY  engager_id, author_id

"""

cursor.execute(engagement_query)
results = cursor.fetchall()
# print(results)
data = defaultdict(int)

for a, b, value in results:
    key = (min(a, b), max(a, b))
    data[key] += value
result_list = [(k[0], k[1], v) for k, v in data.items()]

result_list.sort(key=lambda x: x[2], reverse=True)

print("First few results:")
for i in range(10):
    print(result_list[i])

print("Top 3")
for i in range(3):
    user1_id, user2_id, count = result_list[i]
    
    cursor.execute("SELECT username FROM users WHERE id = ?", (user1_id,))
    user1_result = cursor.fetchone()
    user1_name = user1_result[0] if user1_result else f"User_{user1_id}"
    
    # Get username for second user
    cursor.execute("SELECT username FROM users WHERE id = ?", (user2_id,))
    user2_result = cursor.fetchone()
    user2_name = user2_result[0] if user2_result else f"User_{user2_id}"
    
    print(f"{i+1}. {user1_name}  {user2_name}: {count} interactions")

conn.close()