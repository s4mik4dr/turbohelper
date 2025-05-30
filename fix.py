import sys

def fix_app_py():
    lines = []
    with open('app.py', 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    if len(lines) < 3650:
        print("Файл слишком короткий")
        return
    
    skip_start = 3623  # строка с началом дублирующегося роута
    skip_end = 3630    # примерная строка конца функции get_favorites
    
    # Найдем точное окончание функции get_favorites
    for i in range(skip_start + 1, min(skip_end + 10, len(lines))):
        if lines[i].strip().startswith('if __name__') or lines[i].strip().startswith('@app.route'):
            skip_end = i - 1
            break
    
    print(f"Удаляем строки с {skip_start} по {skip_end}")
    
    # Создаем новый файл без дублирующихся строк
    with open('app_fixed.py', 'w', encoding='utf-8') as f:
        for i, line in enumerate(lines):
            if i < skip_start or i > skip_end:
                f.write(line)
    
    print("Файл app_fixed.py создан успешно")

if __name__ == "__main__":
    fix_app_py() 