import sqlite3
import pandas as pd
from pathlib import Path

# Пути
DB_PATH = 'data/feedback.db'
OUTPUT_DIR = Path('data')
OUTPUT_DIR.mkdir(exist_ok=True)


def get_stats():
    """Получить статистику по отзывам"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('SELECT COUNT(*) FROM feedbacks')
    total = cursor.fetchone()[0]
    
    cursor.execute('''
        SELECT COUNT(*) FROM feedbacks 
        WHERE model_verdict != user_verdict AND user_verdict != 'other'
    ''')
    mismatches = cursor.fetchone()[0]
    
    cursor.execute('SELECT user_verdict, COUNT(*) FROM feedbacks GROUP BY user_verdict')
    verdict_dist = dict(cursor.fetchall())
    
    conn.close()
    
    return {
        'total_feedback': total,
        'mismatches': mismatches,
        'verdict_distribution': verdict_dist,
    }


def export_new_examples():
    """Экспорт новых примеров для дообучения модели"""
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query('''
        SELECT DISTINCT url, user_verdict
        FROM feedbacks
        WHERE user_verdict IN ('dangerous', 'safe')
    ''', conn)
    conn.close()
    
    if df.empty:
        print("   ⚠️ Нет новых примеров для обучения")
        return pd.DataFrame()
    
    df['label'] = df['user_verdict'].map({'dangerous': 1, 'safe': 0})
    df = df.dropna(subset=['label'])
    df['label'] = df['label'].astype(int)
    
    result = df[['url', 'label']]
    result.to_csv(OUTPUT_DIR / 'new_training_examples.csv', index=False)
    print(f"   ✅ Найдено {len(result)} новых примеров для обучения")
    
    return result


def clear_database():
    """Полностью очищает БД"""
    print("\n🧹 ОЧИСТКА БАЗЫ ДАННЫХ")
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('SELECT COUNT(*) FROM feedbacks')
    before = cursor.fetchone()[0]
    
    cursor.execute('DELETE FROM feedbacks')
    cursor.execute('DELETE FROM sqlite_sequence WHERE name="feedbacks"')
    
    conn.commit()
    conn.close()
    
    print(f"   ✅ Удалено записей: {before}")
    
    if before > 0:
        conn = sqlite3.connect(DB_PATH)
        conn.execute('VACUUM')
        conn.close()
        print(f"   ✅ БД оптимизирована")


# ОСНОВНОЙ ЗАПУСК 
if __name__ == '__main__':
    print("\n" + "="*50)
    print("📊 ЭКСПОРТ ОТЗЫВОВ ИЗ БД")
    print("="*50)
    
    # 1. Статистика
    print("\n📈 СТАТИСТИКА:")
    stats = get_stats()
    print(f"   Всего отзывов: {stats['total_feedback']}")
    print(f"   Ошибок модели: {stats['mismatches']}")
    print(f"   Распределение: {stats['verdict_distribution']}")
    
    # 2. Экспорт для обучения
    print("\n🎓 ЭКСПОРТ ДЛЯ ОБУЧЕНИЯ:")
    export_new_examples()
    
    # 3. Очистка БД
    clear_database()
    
    print("\n" + "="*50)
    print("✅ ГОТОВО!")
    print("="*50)
    print("\n📁 Создан файл:")
    print("   • data/new_training_examples.csv - для дообучения")
    print("\n🗑️ БД полностью очищена!")