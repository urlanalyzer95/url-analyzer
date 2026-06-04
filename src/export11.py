import sqlite3
import pandas as pd
from pathlib import Path

DB_PATH = 'data/feedback.db'
OUTPUT_DIR = Path('data')

print(" ЭКСПОРТ ДЛЯ ДОБУЧЕНИЯ МОДЕЛИ")

# Экспорт новых примеров для обучения
conn = sqlite3.connect(DB_PATH)
df = pd.read_sql_query('''
    SELECT DISTINCT url, user_verdict
    FROM feedbacks
    WHERE user_verdict IN ('dangerous', 'safe')
    ORDER BY timestamp DESC
''', conn)
conn.close()

if df.empty:
    print(" Нет новых примеров для обучения")
else:
    # Конвертируем в числа
    df['label'] = df['user_verdict'].map({
        'dangerous': 1,
        'safe': 0
    })
    df = df.dropna(subset=['label'])
    df['label'] = df['label'].astype(int)
    
    # Сохраняем
    result = df[['url', 'label']]
    result.to_csv(OUTPUT_DIR / 'new_training_examples.csv', index=False)
    print(f" Экспортировано {len(result)} примеров")

