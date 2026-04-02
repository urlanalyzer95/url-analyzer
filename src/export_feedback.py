# Создай файл: src/export_feedback.py
import sys
import pandas as pd
import sqlite3
from pathlib import Path
# В начало export_feedback.py

sys.path.append(str(Path(__file__).parent.parent))  
from feedback_system import FeedbackSystem


# Инициализация
fb = FeedbackSystem()

# 1. Получаем статистику
print("📊 СТАТИСТИКА ОБРАТНОЙ СВЯЗИ:")
stats = fb.get_stats()
for key, value in stats.items():
    print(f"   {key}: {value}")

# 2. Экспортируем все отзывы
print("\n📥 ЭКСПОРТ ОТЗЫВОВ...")
conn = sqlite3.connect('data/feedback.db')

# Все отзывы
all_feedback = pd.read_sql_query("SELECT * FROM feedbacks", conn)
all_feedback.to_csv('data/feedback_export.csv', index=False)
all_feedback.to_json('data/feedback_export.json', orient='records', indent=2)

# Только ошибочные предсказания (самые ценные!)
misclassified = fb.get_misclassified(limit=1000)
if not misclassified.empty:
    misclassified.to_csv('data/misclassified_urls.csv', index=False)
    print(f"✅ Найдено {len(misclassified)} ошибочных предсказаний")

# Новые примеры для дообучения
new_examples = fb.get_new_examples(min_confirmations=1)
if not new_examples.empty:
    new_examples.to_csv('data/new_training_examples.csv', index=False)
    print(f"✅ Найдено {len(new_examples)} новых примеров")

conn.close()
print("\n✅ ЭКСПОРТ ЗАВЕРШЁН!")
print("   • data/feedback_export.csv - все отзывы")
print("   • data/misclassified_urls.csv - ошибки модели")
print("   • data/new_training_examples.csv - для дообучения")