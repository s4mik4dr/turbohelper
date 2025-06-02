import sqlite3
conn = sqlite3.connect('D:/cds/TurboParser/instance/users.db')
cursor = conn.cursor()
cursor.execute('SELECT * FROM user')
users = cursor.fetchall()
for user in users:
    print(user)
conn.close()