import sqlite3
import os
from datetime import datetime

# Путь к файлу базы данных
db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance', 'users.db')

def migrate_database():
    """
    Мигрирует базу данных, добавляя таблицу для избранных каналов пользователей
    """
    print(f"Попытка обновления базы данных по пути: {db_path}")
    
    if not os.path.exists(db_path):
        print(f"Файл базы данных не найден по пути: {db_path}")
        return False
    
    try:
        # Подключение к базе данных
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        print("Подключение к базе данных успешно")
        
        # Проверяем, существует ли уже таблица user_favorite
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='user_favorite'")
        if cursor.fetchone():
            print("Таблица user_favorite уже существует")
        else:
            # Создаем таблицу user_favorite
            cursor.execute('''
            CREATE TABLE user_favorite (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                channel TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES user (id),
                UNIQUE (user_id, channel)
            )
            ''')
            
            # Сохраняем изменения
            conn.commit()
            print("Таблица user_favorite успешно создана")
            
            # Загружаем текущие избранные каналы из JSON файла, если он существует
            import json
            favorites_file = os.path.join('uploads', 'telegram_favorites.json')
            
            if os.path.exists(favorites_file):
                print(f"Найден файл с общими избранными каналами: {favorites_file}")
                
                with open(favorites_file, 'r', encoding='utf-8') as f:
                    favorites = json.load(f)
                
                print(f"Загружено {len(favorites)} каналов из общего файла избранных")
                
                # Получаем список пользователей
                cursor.execute("SELECT id FROM user")
                users = cursor.fetchall()
                
                # Для каждого пользователя добавляем все общие каналы как избранные
                for user in users:
                    user_id = user[0]
                    print(f"Добавляем каналы для пользователя ID {user_id}")
                    
                    for channel in favorites:
                        try:
                            cursor.execute(
                                "INSERT INTO user_favorite (user_id, channel, created_at) VALUES (?, ?, ?)",
                                (user_id, channel, datetime.now().isoformat())
                            )
                            print(f"  Добавлен канал {channel}")
                        except sqlite3.IntegrityError:
                            print(f"  Канал {channel} уже существует для пользователя {user_id}")
                
                # Сохраняем изменения
                conn.commit()
                print("Миграция данных из JSON файла в базу данных завершена")
            else:
                print("Файл с общими избранными каналами не найден")
        
        # Закрываем соединение с базой данных
        conn.close()
        print("Соединение с базой данных закрыто")
        
        return True
    except Exception as e:
        print(f"Ошибка при миграции базы данных: {str(e)}")
        return False

if __name__ == "__main__":
    # Выполняем миграцию базы данных
    result = migrate_database()
    print(f"Результат миграции: {'успешно' if result else 'ошибка'}") 