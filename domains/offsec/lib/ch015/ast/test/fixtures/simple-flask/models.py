import sqlite3

db = sqlite3.connect('app.db')

def get_user(user_id):
    cursor = db.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cursor.fetchone()

def create_user(name, email):
    db.execute(f"INSERT INTO users (name, email) VALUES ('{name}', '{email}')")
    db.commit()
    return {"status": "ok"}
