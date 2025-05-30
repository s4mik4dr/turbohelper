#!/usr/bin/env python
"""
Скрипт для исправления проблемы с лишним закрывающим тегом endblock в шаблоне holdings.html
"""
import os
import shutil
from datetime import datetime

def fix_template():
    """Исправляет проблему с лишним закрывающим тегом endblock в шаблоне"""
    template_path = os.path.join('templates', 'holdings.html')
    backup_path = os.path.join('templates', f'holdings_backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.html')
    
    # Проверяем, существует ли файл шаблона
    if not os.path.exists(template_path):
        print(f"Файл {template_path} не найден")
        return False
    
    # Создаем резервную копию файла
    shutil.copy2(template_path, backup_path)
    print(f"Создана резервная копия: {backup_path}")
    
    # Читаем содержимое файла
    with open(template_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    # Подсчитываем количество открывающих и закрывающих тегов block
    open_blocks = 0
    close_blocks = 0
    
    for line in lines:
        if '{% block' in line and not '{% endblock' in line:
            open_blocks += 1
        if '{% endblock' in line:
            close_blocks += 1
    
    print(f"Найдено {open_blocks} открывающих и {close_blocks} закрывающих тегов block")
    
    # Если закрывающих тегов больше, чем открывающих, удаляем лишний
    if close_blocks > open_blocks:
        # Находим последнюю строку с закрывающим тегом
        last_endblock = None
        for i in range(len(lines) - 1, -1, -1):
            if '{% endblock %}' in lines[i]:
                if last_endblock is None:
                    last_endblock = i
                else:
                    # Найден предпоследний закрывающий тег - это правильный тег для блока scripts
                    # Удаляем последний (лишний) закрывающий тег
                    print(f"Удаляем лишний тег endblock в строке {last_endblock + 1}")
                    lines.pop(last_endblock)
                    break
    
        # Записываем исправленный файл
        with open(template_path, 'w', encoding='utf-8') as f:
            f.writelines(lines)
        
        print("Файл успешно исправлен")
        return True
    else:
        print("Нет лишних закрывающих тегов, файл не изменен")
        return False

if __name__ == "__main__":
    fix_template() 