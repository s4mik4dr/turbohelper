import sqlite3
import os
import json
from pprint import pprint

# Путь к файлу базы данных
db_path = 'instance/users.db'

# Проверка существования файла
if not os.path.exists(db_path):
    print(f"Ошибка: файл базы данных {db_path} не найден")
    exit(1)

# Подключение к базе данных
try:
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    print(f"Подключение к базе данных {db_path} успешно установлено\n")
except Exception as e:
    print(f"Ошибка при подключении к базе данных: {str(e)}")
    exit(1)

# Получение списка таблиц
print("=== СПИСОК ТАБЛИЦ ===")
cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = cursor.fetchall()

if not tables:
    print("База данных не содержит таблиц")
    exit(0)

for table in tables:
    table_name = table[0]
    print(f"\n{'=' * 20} ТАБЛИЦА: {table_name} {'=' * 20}")
    
    # Получение информации о структуре таблицы
    cursor.execute(f"PRAGMA table_info({table_name})")
    columns = cursor.fetchall()
    
    print("\nСтруктура таблицы:")
    for col in columns:
        col_id, col_name, col_type, col_notnull, col_default, col_pk = col
        print(f"  {col_name:20} | {col_type:10} | {'NOT NULL' if col_notnull else 'NULL':<10} | {'PRIMARY KEY' if col_pk else '':<12} | {'DEFAULT: ' + str(col_default) if col_default is not None else ''}")
    
    # Получение данных таблицы
    cursor.execute(f"SELECT * FROM {table_name} LIMIT 10")
    rows = cursor.fetchall()
    
    column_names = [col[1] for col in columns]
    
    print(f"\nСодержимое таблицы (до 10 записей):")
    if not rows:
        print("  Таблица пуста")
    else:
        # Вывод заголовков
        header = " | ".join([f"{col:20}" for col in column_names])
        print(f"  {header}")
        print(f"  {'-' * len(header)}")
        
        # Вывод данных
        for row in rows:
            row_formatted = []
            for i, value in enumerate(row):
                # Для строковых значений ограничиваем длину
                if isinstance(value, str) and len(value) > 20:
                    value = value[:17] + "..."
                row_formatted.append(f"{str(value)[:20]:20}")
            print(f"  {' | '.join(row_formatted)}")

print("\n=== СТАТИСТИКА ===")
# Получение количества записей в каждой таблице
for table in tables:
    table_name = table[0]
    cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
    count = cursor.fetchone()[0]
    print(f"Таблица {table_name:20}: {count} записей")

# Закрытие соединения
conn.close() 