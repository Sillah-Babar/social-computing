import sqlite3

# Connect to your database
conn = sqlite3.connect('database.sqlite')
cursor = conn.cursor()

# First, check if the table exists
cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='reports'")
existing_table = cursor.fetchone()

if existing_table:
    print("⚠️  Reports table already exists. Dropping it...")
    cursor.execute("DROP TABLE reports")
    print("✓ Old table dropped")

# Create the reports table with correct schema
print("Creating reports table...")
cursor.execute('''
CREATE TABLE reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER NOT NULL,
    reporter_id INTEGER NOT NULL,
    reason TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
    FOREIGN KEY (reporter_id) REFERENCES users(id) ON DELETE CASCADE
)
''')

# Create indexes for better performance
cursor.execute('''
CREATE INDEX idx_reports_post_id ON reports(post_id)
''')

cursor.execute('''
CREATE INDEX idx_reports_reporter_id ON reports(reporter_id)
''')

# Commit the changes
conn.commit()

# Verify the table was created
cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='reports'")
result = cursor.fetchone()

if result:
    print("✓ Reports table created successfully!")
    
    # Show table structure
    cursor.execute("PRAGMA table_info(reports)")
    columns = cursor.fetchall()
    print("\nTable structure:")
    for col in columns:
        print(f"  - {col[1]} ({col[2]})")
    
    # Show indexes
    cursor.execute("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='reports'")
    indexes = cursor.fetchall()
    print("\nIndexes:")
    for idx in indexes:
        print(f"  - {idx[0]}")
else:
    print("✗ Failed to create reports table")

# Close the connection
conn.close()