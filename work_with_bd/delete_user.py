import sqlite3
import os

# Путь к базе данных
db_path = 'instance/users.db'

def delete_user(user_id):
    """
    Удаляет пользователя с указанным ID из базы данных.
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
        
        # Получаем список всех пользователей перед удалением
        cursor.execute("SELECT id, email, first_name, last_name FROM user")
        users = cursor.fetchall()
        print(f"Найдено пользователей в базе: {len(users)}")
        
        for user in users:
            print(f"ID: {user[0]}, Email: {user[1]}, Имя: {user[2]}, Фамилия: {user[3]}")
        
        # Проверяем, существует ли пользователь с указанным ID
        cursor.execute("SELECT id, email, first_name, last_name FROM user WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        
        if not user:
            print(f"Пользователь с ID {user_id} не найден в базе данных")
            conn.close()
            return False
        
        print(f"Найден пользователь для удаления: ID: {user[0]}, Email: {user[1]}, Имя: {user[2]}, Фамилия: {user[3]}")
        
        # Удаляем пользователя из таблицы user
        cursor.execute("DELETE FROM user WHERE id = ?", (user_id,))
        
        # Проверяем, сколько строк было удалено
        deleted_rows = cursor.rowcount
        print(f"Удалено строк из таблицы user: {deleted_rows}")
        
        # Удаляем связанные записи из других таблиц, если есть
        cursor.execute("DELETE FROM user_log WHERE user_id = ?", (user_id,))
        deleted_logs = cursor.rowcount
        print(f"Удалено строк из таблицы user_log: {deleted_logs}")
        
        # Сохраняем изменения
        conn.commit()
        print("Изменения сохранены в базе данных")
        
        # Проверяем, что пользователь действительно удален
        cursor.execute("SELECT id FROM user WHERE id = ?", (user_id,))
        if cursor.fetchone() is None:
            print(f"Пользователь с ID {user_id} успешно удален из базы данных")
            result = True
        else:
            print(f"Пользователь с ID {user_id} по-прежнему существует в базе данных")
            result = False
        
        # Получаем список пользователей после удаления
        cursor.execute("SELECT id, email, first_name, last_name FROM user")
        users_after = cursor.fetchall()
        print(f"Осталось пользователей в базе: {len(users_after)}")
        
        for user in users_after:
            print(f"ID: {user[0]}, Email: {user[1]}, Имя: {user[2]}, Фамилия: {user[3]}")
        
        # Закрываем соединение
        conn.close()
        return result
        
    except Exception as e:
        print(f"Произошла ошибка при удалении пользователя: {str(e)}")
        return False

def make_admin(user_id):
    """
    Назначает пользователя администратором.
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
        cursor.execute("SELECT id, email, first_name, last_name, is_admin FROM user WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        
        if not user:
            print(f"Пользователь с ID {user_id} не найден в базе данных")
            conn.close()
            return False
        
        print(f"Найден пользователь: ID: {user[0]}, Email: {user[1]}, Имя: {user[2]}, Фамилия: {user[3]}, Админ: {user[4]}")
        
        # Если пользователь уже администратор
        if user[4] == 1:
            print(f"Пользователь с ID {user_id} уже является администратором")
            conn.close()
            return True
        
        # Назначаем пользователя администратором
        cursor.execute("UPDATE user SET is_admin = 1 WHERE id = ?", (user_id,))
        
        # Проверяем, сколько строк было обновлено
        updated_rows = cursor.rowcount
        print(f"Обновлено строк в таблице user: {updated_rows}")
        
        # Сохраняем изменения
        conn.commit()
        print("Изменения сохранены в базе данных")
        
        # Проверяем, что права действительно обновлены
        cursor.execute("SELECT is_admin FROM user WHERE id = ?", (user_id,))
        is_admin = cursor.fetchone()[0]
        if is_admin == 1:
            print(f"Пользователь с ID {user_id} успешно назначен администратором")
            result = True
        else:
            print(f"Не удалось назначить пользователя с ID {user_id} администратором")
            result = False
        
        # Закрываем соединение
        conn.close()
        return result
        
    except Exception as e:
        print(f"Произошла ошибка при назначении администратором: {str(e)}")
        return False

if __name__ == "__main__":
    # Назначаем пользователя с ID 2 администратором
    user_id_to_update = 2
    
    print(f"Назначение пользователя с ID {user_id_to_update} администратором...")
    success = make_admin(user_id_to_update)
    
    if success:
        print("Операция выполнена успешно")
    else:
        print("Операция не выполнена из-за ошибки") 