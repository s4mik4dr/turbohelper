#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import json
import time
import random
import argparse
from datetime import datetime
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException

def setup_driver():
    """Настраивает и возвращает драйвер Chrome для Selenium"""
    chrome_options = Options()
    chrome_options.add_argument("--headless")  # Запуск в фоновом режиме
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--window-size=1920,1080")
    chrome_options.add_argument("--disable-notifications")
    chrome_options.add_argument("--disable-popup-blocking")
    chrome_options.add_argument("--disable-extensions")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-infobars")
    chrome_options.add_argument("--disable-web-security")

    # Добавляем User-Agent
    chrome_options.add_argument("--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36")
    
    return webdriver.Chrome(options=chrome_options)

def save_messages_to_json(messages, channel, output_dir="telegram_cache"):
    """Сохраняет сообщения в JSON файл"""
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        
    output_file = os.path.join(output_dir, f"{channel}.json")
    
    # Форматируем данные для сохранения
    data = {
        'channel': channel,
        'channel_name': f"@{channel}",
        'messages': messages,
        'total_messages': len(messages),
        'last_update': datetime.now().isoformat(),
        'status': 'complete'
    }
    
    # Сохраняем в JSON
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    
    print(f"Сохранено {len(messages)} сообщений в файл {output_file}")
    return output_file

def parse_telegram_channel(channel, max_messages=None, max_scroll_attempts=200):
    """Парсит канал Telegram через веб-интерфейс, используя Selenium для имитации прокрутки"""
    print(f"Начинаем парсинг канала @{channel}")
    driver = setup_driver()
    
    try:
        # Загружаем страницу канала
        url = f"https://t.me/s/{channel}"
        print(f"Открываем URL: {url}")
        driver.get(url)
        
        # Ждем загрузки страницы
        wait = WebDriverWait(driver, 20)
        wait.until(EC.presence_of_element_located((By.CLASS_NAME, "tgme_page")))
        
        # Проверяем, что канал существует и доступен
        if "This channel is private" in driver.page_source or "You can view and join" in driver.page_source:
            print(f"Канал @{channel} приватный или не существует")
            return []
        
        messages = []
        prev_message_count = 0
        no_new_messages_count = 0
        
        # Прокручиваем страницу вниз для загрузки сообщений
        for scroll_attempt in range(max_scroll_attempts):
            # Получаем текущие сообщения на странице
            message_elements = driver.find_elements(By.CLASS_NAME, "tgme_widget_message_wrap")
            message_count = len(message_elements)
            
            print(f"Прокрутка {scroll_attempt+1}/{max_scroll_attempts}: найдено {message_count} сообщений")
            
            # Проверяем, появились ли новые сообщения
            if message_count == prev_message_count:
                no_new_messages_count += 1
                print(f"Нет новых сообщений (попытка {no_new_messages_count}/3)")
                
                # Если 3 прокрутки подряд не дали новых сообщений, завершаем
                if no_new_messages_count >= 3:
                    print("Достигнут конец истории или нет новых сообщений")
                    break
            else:
                no_new_messages_count = 0
            
            prev_message_count = message_count
            
            # Если достигли лимита сообщений
            if max_messages and message_count >= max_messages:
                print(f"Достигнут лимит сообщений ({max_messages})")
                break
            
            # Прокручиваем страницу вниз
            driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
            
            # Случайная пауза для имитации человеческого поведения и загрузки контента
            time.sleep(2 + random.random() * 3)
        
        # Теперь извлекаем данные из загруженных сообщений
        message_elements = driver.find_elements(By.CLASS_NAME, "tgme_widget_message_wrap")
        print(f"Обработка {len(message_elements)} сообщений...")
        
        for elem in message_elements:
            try:
                # Получаем ID сообщения
                message_id = None
                link_elem = elem.find_element(By.CLASS_NAME, "tgme_widget_message_date")
                if link_elem and link_elem.get_attribute("href"):
                    link = link_elem.get_attribute("href")
                    if "/" in link:
                        message_id = int(link.split("/")[-1])
                
                # Получаем дату
                date_elem = elem.find_element(By.CSS_SELECTOR, ".tgme_widget_message_date time")
                date_str = date_elem.get_attribute("datetime") if date_elem else None
                
                if date_str:
                    message_datetime = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                    date_formatted = message_datetime.strftime("%d.%m.%Y")
                    time_formatted = message_datetime.strftime("%H:%M:%S")
                    date_timestamp = message_datetime.timestamp()
                else:
                    date_formatted = "Неизвестно"
                    time_formatted = "Неизвестно"
                    date_timestamp = 0
                
                # Получаем текст сообщения
                text_elem = elem.find_element(By.CLASS_NAME, "tgme_widget_message_text") if elem.find_elements(By.CLASS_NAME, "tgme_widget_message_text") else None
                text = text_elem.text if text_elem else ""
                
                # Проверяем наличие фото
                photos = elem.find_elements(By.CLASS_NAME, "tgme_widget_message_photo_wrap")
                has_images = len(photos) > 0
                images_count = len(photos)
                
                # Создаем превью (первые 10 слов)
                words = text.split()
                preview = ' '.join(words[:10]) + '...' if len(words) > 10 else text
                
                # Формируем объект сообщения
                message = {
                    'id': message_id,
                    'date': date_formatted,
                    'time': time_formatted,
                    'date_timestamp': date_timestamp,
                    'text': text,
                    'preview': preview,
                    'link': link_elem.get_attribute("href") if link_elem else "",
                    'has_images': has_images,
                    'images_count': images_count
                }
                
                messages.append(message)
            except Exception as e:
                print(f"Ошибка при обработке сообщения: {str(e)}")
                continue
        
        # Сортируем сообщения по убыванию даты (новые первыми)
        messages.sort(key=lambda x: x.get('date_timestamp', 0), reverse=True)
        print(f"Успешно получено {len(messages)} сообщений из канала @{channel}")
        
        return messages
        
    except Exception as e:
        print(f"Ошибка при парсинге канала: {str(e)}")
        return []
    finally:
        driver.quit()

def main():
    parser = argparse.ArgumentParser(description='Скрипт для парсинга сообщений из канала Telegram')
    parser.add_argument('channel', help='Имя канала Telegram без символа @')
    parser.add_argument('--max-messages', type=int, default=None, help='Максимальное количество сообщений для загрузки')
    parser.add_argument('--max-scrolls', type=int, default=200, help='Максимальное количество прокруток страницы')
    parser.add_argument('--output-dir', default='uploads/telegram_cache', help='Директория для сохранения результатов')
    
    args = parser.parse_args()
    
    # Удаляем символ @ из начала имени канала, если есть
    channel = args.channel.lstrip('@')
    
    # Запускаем парсинг
    start_time = time.time()
    messages = parse_telegram_channel(channel, args.max_messages, args.max_scrolls)
    end_time = time.time()
    
    # Сохраняем результаты
    if messages:
        output_file = save_messages_to_json(messages, channel, args.output_dir)
        print(f"Результаты сохранены в {output_file}")
    else:
        print("Не удалось получить сообщения из канала")
    
    print(f"Время выполнения: {end_time - start_time:.2f} сек")

if __name__ == "__main__":
    main() 