import sqlite3
import os
from datetime import datetime

# Путь к файлу базы данных
db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance', 'users.db')

def migrate_database():
    """
    Мигрирует базу данных, добавляя новые поля в таблицу пользователей
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
        
        # Проверяем, существуют ли уже поля last_ip и last_login
        cursor.execute("PRAGMA table_info(user)")
        columns = [column[1] for column in cursor.fetchall()]
        
        columns_to_add = []
        if 'last_ip' not in columns:
            columns_to_add.append(('last_ip', 'TEXT'))
        
        if 'last_login' not in columns:
            columns_to_add.append(('last_login', 'TIMESTAMP'))
        
        # Если нет полей для добавления, завершаем работу основной миграции
        if not columns_to_add:
            print("Все необходимые поля уже существуют в таблице user.")
        else:
            print(f"Поля для добавления: {columns_to_add}")
            
            # Добавляем новые поля
            for column_name, column_type in columns_to_add:
                try:
                    cursor.execute(f"ALTER TABLE user ADD COLUMN {column_name} {column_type}")
                    print(f"Поле '{column_name}' успешно добавлено")
                except sqlite3.OperationalError as e:
                    print(f"Ошибка при добавлении поля '{column_name}': {e}")
        
        # Проверяем, существует ли таблица user_favorite
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='user_favorite'")
        user_favorite_exists = cursor.fetchone() is not None
        
        if not user_favorite_exists:
            print("Создание таблицы user_favorite...")
            cursor.execute('''
                CREATE TABLE user_favorite (
                    id INTEGER PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    channel TEXT NOT NULL,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES user (id)
                )
            ''')
            print("Таблица user_favorite успешно создана")
            
            # Миграция данных из старого JSON файла, если он существует
            import json
            favorites_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads', 'telegram_favorites.json')
            
            if os.path.exists(favorites_file):
                print(f"Найден старый файл с избранными каналами: {favorites_file}")
                try:
                    with open(favorites_file, 'r', encoding='utf-8') as f:
                        favorites = json.load(f)
                    
                    # Получаем всех пользователей
                    cursor.execute("SELECT id FROM user")
                    user_ids = [row[0] for row in cursor.fetchall()]
                    
                    if user_ids and favorites:
                        print(f"Перенос {len(favorites)} каналов для {len(user_ids)} пользователей...")
                        # Добавляем избранные каналы для всех пользователей
                        for user_id in user_ids:
                            for channel in favorites:
                                cursor.execute(
                                    "INSERT INTO user_favorite (user_id, channel) VALUES (?, ?)",
                                    (user_id, channel)
                                )
                        print(f"Данные из JSON файла успешно перенесены в таблицу user_favorite")
                except Exception as e:
                    print(f"Ошибка при миграции данных из JSON: {e}")
            else:
                print("Старый файл с избранными каналами не найден")
        else:
            print("Таблица user_favorite уже существует")
        
        # Сохраняем изменения
        conn.commit()
        conn.close()
        
        print("Миграция базы данных успешно завершена")
        return True
        
    except Exception as e:
        print(f"Ошибка при миграции базы данных: {e}")
        return False

if __name__ == "__main__":
    migrate_database() 