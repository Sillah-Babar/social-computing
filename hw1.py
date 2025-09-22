import sqlite3

sqliteConnection = sqlite3.connect('database.sqlite')

# Connect to the database
cursor = sqliteConnection.cursor()
cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")

print("List of tables\n")
list_of_tuples = cursor.fetchall()
print(list_of_tuples)
for table_tup in list_of_tuples:
    table_name = table_tup[0]
    print("---------------------------------")
    print("Table Name: ", table_name)
    print("Columns: ")
   
    column_names = cursor.execute(f'''PRAGMA table_info('{table_name}')''')    
    columns__description = cursor.fetchall() 
    print(columns__description)
    
    
    select_statement = f'''SELECT * FROM {table_name} LIMIT 5'''
    cursor.execute(select_statement)
    output = cursor.fetchall()

    index = 1
    for obj in output:
        print("row: ", index)
        index+=1
        print(obj)
    print("---------------------------------")



##Task 1.2
query = """
SELECT count(id)
FROM users
WHERE id NOT IN (SELECT DISTINCT user_id FROM posts)
  AND id NOT IN (SELECT DISTINCT user_id FROM comments)
  AND id NOT IN (SELECT DISTINCT user_id FROM reactions)
"""

cursor.execute(query)
results = cursor.fetchall()
print("ans: ", results)

## Task 1.3

query_3 = """SELECT 
    u.username,
    (COUNT(DISTINCT c.id) + COUNT(DISTINCT r.id)) AS engagement
FROM users u
LEFT JOIN posts p ON u.id = p.user_id
LEFT JOIN comments c ON p.id = c.post_id
LEFT JOIN reactions r ON p.id = r.post_id
GROUP BY u.username
ORDER BY engagement DESC
LIMIT 5;"""


cursor.execute(query_3)
results = cursor.fetchall()
print("ans: ", results)