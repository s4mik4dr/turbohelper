#!/usr/bin/env python
# -*- coding: utf-8 -*-

import requests
import json
import sys

# API ключ для Checko.ru
API_KEY = "ZXHNsb6ZeNjtCsRk"

def test_company_api(inn="7736050003"):
    """
    Тестирует API Checko.ru на получение данных о компании
    """
    base_url = "https://api.checko.ru/v2"
    headers = {
        "Authorization": f"Token {API_KEY}"
    }
    
    print(f"Тестирование API для компании с ИНН: {inn}")
    print(f"Используется ключ API: {API_KEY}")
    print(f"URL API: {base_url}")
    print("-" * 80)
    
    # URL для получения данных компании по ИНН
    company_url = f"{base_url}/company/inn/{inn}"
    finances_url = f"{base_url}/finances/inn/{inn}/years"
    
    # Тест 1: запрос данных компании
    print("Тест 1: Запрос данных компании")
    try:
        print(f"URL запроса: {company_url}")
        company_response = requests.get(company_url, headers=headers, timeout=30)
        print(f"Код ответа: {company_response.status_code}")
        
        if company_response.status_code == 200:
            data = company_response.json()
            print("Ответ успешно получен и разобран как JSON")
            if "data" in data:
                print(f"Найдена компания: {data['data'].get('НаимСокр', 'Имя не найдено')}")
                if "ОКВЭД" in data["data"]:
                    print(f"Основной ОКВЭД: {data['data']['ОКВЭД'].get('Код', 'не найден')}")
                if "ОКВЭДДоп" in data["data"] and isinstance(data["data"]["ОКВЭДДоп"], list):
                    print(f"Дополнительных ОКВЭД: {len(data['data']['ОКВЭДДоп'])}")
            else:
                print("Структура данных не содержит ожидаемый элемент 'data'")
                print("Структура ответа:", list(data.keys()))
        else:
            print(f"Ошибка при получении данных компании: {company_response.status_code}")
            print("Текст ответа:", company_response.text)
    except Exception as e:
        print(f"Исключение при получении данных компании: {str(e)}")
    
    print("\n" + "-" * 80)
    
    # Тест 2: запрос финансовых данных
    print("Тест 2: Запрос финансовых данных")
    try:
        print(f"URL запроса: {finances_url}")
        finance_response = requests.get(finances_url, headers=headers, timeout=30)
        print(f"Код ответа: {finance_response.status_code}")
        
        if finance_response.status_code == 200:
            data = finance_response.json()
            print("Ответ успешно получен и разобран как JSON")
            if "data" in data and "years" in data["data"]:
                years = data["data"]["years"]
                print(f"Найдено финансовых отчетов: {len(years)}")
                
                if len(years) > 0:
                    latest_year = years[0]
                    print(f"Последний год: {latest_year.get('year', 'не указан')}")
                    print(f"Выручка: {latest_year.get('Выручка', 'не указана')}")
                    print(f"Чистая прибыль: {latest_year.get('ЧистПрибыль', 'не указана')}")
            else:
                print("Структура финансовых данных не содержит ожидаемые элементы")
                print("Структура ответа:", json.dumps(data, ensure_ascii=False, indent=2)[:1000] + "...")
        else:
            print(f"Ошибка при получении финансовых данных: {finance_response.status_code}")
            print("Текст ответа:", finance_response.text)
    except Exception as e:
        print(f"Исключение при получении финансовых данных: {str(e)}")
    
    print("\n" + "=" * 80)
    print("Тестирование API завершено")

if __name__ == "__main__":
    # Если передан ИНН как аргумент командной строки, используем его
    inn = sys.argv[1] if len(sys.argv) > 1 else "7736050003" # ПАО "Газпром"
    test_company_api(inn) 