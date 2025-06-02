import sqlite3
import os
from app import app, User, db, login_user
from flask import request, session
import datetime

# Путь к базе данных
db_path = 'instance/users.db'

def check_feature_access():
    """
    Проверяет содержимое таблицы feature_access и возможные проблемы
    """
    try:
        # Проверяем существование файла БД
        if not os.path.exists(db_path):
            print(f"Ошибка: файл базы данных {db_path} не найден")
            return False
        
        print(f"Файл базы данных найден: {db_path}")
        
        # Подключаемся к базе данных
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        print("Успешное подключение к базе данных")
        
        # Проверяем существование таблицы feature_access
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='feature_access'")
        if not cursor.fetchone():
            print("Таблица feature_access не существует в базе данных!")
            print("Создаю таблицу feature_access...")
            cursor.execute('''
                CREATE TABLE feature_access (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_type VARCHAR(20) NOT NULL,
                    target_id VARCHAR(100) NOT NULL,
                    feature VARCHAR(50) NOT NULL,
                    access BOOLEAN NOT NULL DEFAULT 1
                )
            ''')
            conn.commit()
            print("Таблица feature_access успешно создана")
        
        # Получаем все записи из таблицы feature_access
        cursor.execute("SELECT * FROM feature_access")
        rows = cursor.fetchall()
        
        print(f"\nНайдено записей в таблице feature_access: {len(rows)}")
        
        if rows:
            print("\nID | target_type | target_id | feature | access")
            print("-" * 60)
            for row in rows:
                print(" | ".join(str(x) for x in row))
        else:
            print("Таблица feature_access пуста. Добавление тестовых записей...")
            
            # Получаем существующие отделы из базы данных
            cursor.execute("SELECT DISTINCT department FROM user")
            departments = [dept[0] for dept in cursor.fetchall()]
            
            # Получаем существующих пользователей
            cursor.execute("SELECT id FROM user")
            user_ids = [str(user_id[0]) for user_id in cursor.fetchall()]
            
            # Список доступных функций
            features = ['parser', 'holdings', 'qr', 'ai', 'analytics', 'dashboard', 'competitors']
            
            # Добавляем тестовую запись для первого отдела, если он есть
            if departments:
                for feature in features:
                    cursor.execute('''
                        INSERT INTO feature_access (target_type, target_id, feature, access)
                        VALUES (?, ?, ?, ?)
                    ''', ('department', departments[0], feature, True))
                print(f"Добавлены тестовые записи для отдела {departments[0]}")
            
            # Добавляем тестовую запись для первого пользователя, если он есть
            if user_ids:
                for feature in features:
                    cursor.execute('''
                        INSERT INTO feature_access (target_type, target_id, feature, access)
                        VALUES (?, ?, ?, ?)
                    ''', ('user', user_ids[0], feature, True))
                print(f"Добавлены тестовые записи для пользователя с ID {user_ids[0]}")
            
            conn.commit()
            
            # Выводим добавленные записи
            cursor.execute("SELECT * FROM feature_access")
            rows = cursor.fetchall()
            print(f"\nДобавлено записей: {len(rows)}")
            print("\nID | target_type | target_id | feature | access")
            print("-" * 60)
            for row in rows:
                print(" | ".join(str(x) for x in row))
        
        # Закрываем соединение
        conn.close()
        return True
        
    except Exception as e:
        print(f"Произошла ошибка при проверке feature_access: {str(e)}")
        return False

def check_persistent_login():
    """
    Проверяет постоянный вход пользователя через сессию
    Эта функция должна вызываться при запуске сервера
    """
    with app.app_context():
        try:
            # Проверяем всех пользователей, которые вошли с опцией "запомнить меня"
            users = User.query.filter(User.last_login.isnot(None)).all()
            print(f"Найдено {len(users)} пользователей с сохраненными сессиями")
            
            # Обновляем информацию о последнем входе
            for user in users:
                # Обновляем статистику входа
                print(f"Обновляем данные для пользователя {user.email}")
                user.last_login = datetime.datetime.utcnow()
                
            db.session.commit()
            print("Данные о сессиях пользователей обновлены")
            
        except Exception as e:
            print(f"Ошибка при проверке постоянных логинов: {e}")

if __name__ == "__main__":
    print("Проверка таблицы feature_access...")
    check_feature_access()
    check_persistent_login() 