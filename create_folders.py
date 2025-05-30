#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os

def create_necessary_folders():
    """
    Создает необходимые директории для работы приложения
    """
    # Список необходимых директорий
    directories = [
        os.path.join('static', 'img'),
        os.path.join('static', 'img', 'ai-logos'),
        os.path.join('static', 'css'),
        os.path.join('static', 'js'),
        'uploads',
        os.path.join('uploads', 'profile_pics'),
        os.path.join('uploads', 'telegram_cache'),
        'flask_session',
        'instance',
        'qr_codes'
    ]
    
    # Создаем каждую директорию
    for directory in directories:
        if not os.path.exists(directory):
            try:
                os.makedirs(directory)
                print(f"Директория {directory} успешно создана")
            except Exception as e:
                print(f"Ошибка при создании директории {directory}: {e}")
        else:
            print(f"Папка {directory} уже существует")

if __name__ == "__main__":
    create_necessary_folders()

# Создаем директорию для иконок ИИ
ai_logos_dir = os.path.join('static', 'img', 'ai-logos')
os.makedirs(ai_logos_dir, exist_ok=True)

print(f"Директория {ai_logos_dir} успешно создана") 