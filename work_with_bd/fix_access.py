import sqlite3
import os
from app import app, db, User, FeatureAccess, bcrypt, login_user, session
from flask import request
from datetime import datetime

# Путь к базе данных
db_path = 'instance/users.db'

def add_user_access(user_id):
    """
    Добавляет записи доступа к функциям для указанного пользователя.
    Возвращает True в случае успеха, иначе False.
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
        
        # Проверяем, существует ли пользователь с указанным ID
        cursor.execute("SELECT id, email, first_name, last_name FROM user WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        
        if not user:
            print(f"Пользователь с ID {user_id} не найден в базе данных")
            conn.close()
            return False
        
        print(f"Найден пользователь: ID: {user[0]}, Email: {user[1]}, Имя: {user[2]}, Фамилия: {user[3]}")
        
        # Проверяем, есть ли уже записи для этого пользователя
        cursor.execute("SELECT * FROM feature_access WHERE target_type = 'user' AND target_id = ?", (str(user_id),))
        existing_records = cursor.fetchall()
        
        if existing_records:
            print(f"Найдено {len(existing_records)} существующих записей для пользователя. Удаляем их...")
            cursor.execute("DELETE FROM feature_access WHERE target_type = 'user' AND target_id = ?", (str(user_id),))
            print(f"Удалено {cursor.rowcount} записей")
        
        # Список доступных функций и их статусы
        features = {
            'parser': True,
            'holdings': True,
            'qr': True,
            'ai': True,
            'analytics': True,
            'dashboard': True,
            'competitors': True
        }
        
        # Добавляем записи доступа для пользователя
        for feature, access in features.items():
            cursor.execute('''
                INSERT INTO feature_access (target_type, target_id, feature, access)
                VALUES (?, ?, ?, ?)
            ''', ('user', str(user_id), feature, access))
        
        # Сохраняем изменения
        conn.commit()
        print(f"Добавлено {len(features)} записей доступа для пользователя с ID {user_id}")
        
        # Выводим добавленные записи
        cursor.execute("SELECT * FROM feature_access WHERE target_type = 'user' AND target_id = ?", (str(user_id),))
        rows = cursor.fetchall()
        print("\nID | target_type | target_id | feature | access")
        print("-" * 60)
        for row in rows:
            print(" | ".join(str(x) for x in row))
        
        # Закрываем соединение
        conn.close()
        return True
        
    except Exception as e:
        print(f"Произошла ошибка при добавлении доступа: {str(e)}")
        return False

def fix_html_template():
    """
    Предлагает исправление для HTML шаблона admin.html
    """
    print("\nОшибка в HTML шаблоне admin.html найдена:")
    print("В JavaScript-коде формы доступа к функциям используются неправильные ключи.")
    print("Вот как должен выглядеть исправленный код:")
    print("""
    const featureAccess = {
        target: selector.value,
        features: {
            'parser': document.getElementById('featureParser').checked,
            'holdings': document.getElementById('featureHoldings').checked,
            'qr': document.getElementById('featureQR').checked,
            'ai': document.getElementById('featureAI').checked,
            'analytics': document.getElementById('featureAnalytics').checked,
            'dashboard': document.getElementById('featureDashboard').checked
        }
    };
    """)
    print("Или другой вариант решения - переименовать элементы формы:")
    print("""
    <li>
        <div class="form-check form-switch">
            <input class="form-check-input" type="checkbox" id="parser" checked>
            <label class="form-check-label" for="parser">Парсер новостей</label>
        </div>
    </li>
    ... и аналогично для других функций
    """)
    print("Тогда JavaScript код будет работать корректно.")

def fix_sessions():
    """
    Восстанавливает сессии для пользователей, которые включили опцию "запомнить меня"
    """
    with app.app_context():
        try:
            # Находим всех пользователей с сохраненной датой последнего входа
            users = User.query.filter(User.last_login.isnot(None)).all()
            print(f"Найдено {len(users)} пользователей с сохраненными сессиями")
            
            # Подготавливаем информацию о сессиях
            session_info = []
            for user in users:
                # Создаем метку времени для сравнения
                now = datetime.utcnow()
                last_login = user.last_login
                
                # Считаем разницу в днях
                days_diff = (now - last_login).days if last_login else None
                
                session_info.append({
                    'id': user.id,
                    'email': user.email,
                    'last_ip': user.last_ip,
                    'last_login': last_login.strftime('%Y-%m-%d %H:%M:%S') if last_login else None,
                    'days_since_login': days_diff
                })
            
            # Выводим информацию о сессиях
            for info in session_info:
                print(f"ID: {info['id']}, Email: {info['email']}, IP: {info['last_ip']}, Последний вход: {info['last_login']}, Дней с последнего входа: {info['days_since_login']}")
                
            print("Проверка сессий завершена")
            
        except Exception as e:
            print(f"Ошибка при проверке сессий: {e}")

# Если скрипт запущен напрямую, выполняем обе функции
if __name__ == '__main__':
    print("Исправление доступа к функциям...")
    fix_access()
    print("\nПроверка сессий пользователей...")
    fix_sessions()

    user_id_to_fix = 2
    
    print(f"Добавление доступа к функциям для пользователя с ID {user_id_to_fix}...")
    success = add_user_access(user_id_to_fix)
    
    if success:
        print("\nДоступ к функциям успешно добавлен!")
    else:
        print("\nНе удалось добавить доступ к функциям")
    
    fix_html_template() 