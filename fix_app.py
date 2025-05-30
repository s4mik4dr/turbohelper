#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Скрипт для исправления дублирующейся функции refresh_telegram_cache в app.py
"""

import re
import os
import shutil
from datetime import datetime

def fix_duplicate_route():
    """
    Находит и удаляет дублирующийся маршрут '/api/telegram/refresh_cache' в app.py
    """
    app_path = 'app.py'
    backup_path = f'app_backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.py'
    
    # Создаем резервную копию файла
    shutil.copy2(app_path, backup_path)
    print(f"Создана резервная копия файла: {backup_path}")
    
    with open(app_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Находим все вхождения маршрута
    route_pattern = r"@app\.route\('/api/telegram/refresh_cache', methods=\['POST'\]\)\s+def refresh_telegram_cache\(\):"
    matches = list(re.finditer(route_pattern, content))
    
    if len(matches) < 2:
        print("Дублирующиеся маршруты не найдены.")
        return False
    
    print(f"Найдено {len(matches)} вхождений маршрута '/api/telegram/refresh_cache'")
    
    # Находим начало и конец второго вхождения функции
    second_match = matches[1]
    start_pos = second_match.start()
    
    # Ищем следующий маршрут после второго вхождения или конец файла
    next_route_pattern = r"@app\.route\('/"
    next_match = re.search(next_route_pattern, content[second_match.end():])
    
    if next_match:
        end_pos = second_match.end() + next_match.start() - 1
    else:
        # Если следующий маршрут не найден, удаляем до конца файла
        end_pos = len(content)
    
    # Удаляем второе вхождение функции
    new_content = content[:start_pos] + content[end_pos:]
    
    # Сохраняем изменения
    with open(app_path, 'w', encoding='utf-8') as f:
        f.write(new_content)
    
    print(f"Удалено дублирующееся определение функции refresh_telegram_cache.")
    print(f"Для восстановления исходного файла используйте: {backup_path}")
    return True

def remove_duplicated_endpoint():
    with open('app.py', 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Находим первое появление роута /api/telegram/favorites (GET)
    first_route_match = re.search(r"@app\.route\('\/api\/telegram\/favorites', methods=\['GET'\]\)", content)
    if not first_route_match:
        print("Первый роут не найден, выход")
        return
    
    # Ищем второе появление того же роута
    pattern = r"@app\.route\('\/api\/telegram\/favorites', methods=\['GET'\]\)[^\@]*?def get_favorites\(\):.*?return jsonify\(channels\)"
    match = re.search(pattern, content[first_route_match.end():], re.DOTALL)
    if not match:
        print("Второй роут не найден, выход")
        return
    
    # Вычисляем позиции для удаления
    start_pos = first_route_match.end() + match.start()
    end_pos = first_route_match.end() + match.end()
    
    # Удаляем дублирующийся роут
    new_content = content[:start_pos] + content[end_pos:]
    
    # Записываем результат в новый файл
    with open('app_fixed.py', 'w', encoding='utf-8') as f:
        f.write(new_content)
    
    print("Дублированный роут удален, результат сохранен в app_fixed.py")

def fix_app_py():
    print("Исправление форматирования в app.py")
    
    # Читаем содержимое файла
    with open("app.py", "r", encoding="utf-8") as f:
        content = f.read()
    
    # Находим и заменяем проблемные строки
    # Заменяем определение COMPANY_API_KEY на корректное
    content = re.sub(
        r'# API ключ уже определен выше',
        'COMPANY_API_KEY = API_KEY  # Использовать тот же ключ',
        content
    )
    
    # Находим все случаи использования COMPANY_API_KEY для URL
    content = re.sub(
        r'key={COMPANY_API_KEY}',
        'key={API_KEY}',
        content
    )
    
    # Исправляем форматирование для функции get_company_info
    get_company_info_pattern = r'def get_company_info\(query, search_params=None\):.*?try:.*?search_url = f"{base_url}/search\?key=\{API_KEY\}"'
    fixed_get_company_info = '''def get_company_info(query, search_params=None):
    # Базовый URL API
    base_url = "https://api.checko.ru/v2"
    
    try:
        # Поиск компании по запросу с учетом дополнительных параметров
        search_url = f"{base_url}/search?key={API_KEY}"'''
    
    content = re.sub(get_company_info_pattern, fixed_get_company_info, content, flags=re.DOTALL)
    
    # Записываем исправленное содержимое в файл
    with open("app.py", "w", encoding="utf-8") as f:
        f.write(content)
    
    print("Файл app.py успешно исправлен")

if __name__ == "__main__":
    try:
        result = fix_duplicate_route()
        if result:
            print("Исправление успешно выполнено.")
        else:
            print("Исправление не требуется или не удалось выполнить.")
        remove_duplicated_endpoint()
        fix_app_py()
    except Exception as e:
        print(f"Ошибка при выполнении исправления: {str(e)}") 