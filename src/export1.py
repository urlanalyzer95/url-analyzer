import sqlite3
import pandas as pd
from pathlib import Path
from datetime import datetime

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
    
    cursor.execute('SELECT COUNT(*) FROM feedbacks WHERE is_processed = 0')
    unprocessed = cursor.fetchone()[0]
    
    cursor.execute('SELECT user_verdict, COUNT(*) FROM feedbacks GROUP BY user_verdict')
    verdict_dist = dict(cursor.fetchall())
    
    conn.close()
    
    return {
        'total_feedback': total,
        'mismatches': mismatches,
        'unprocessed': unprocessed,
        'agreements': total - mismatches,
        'verdict_distribution': verdict_dist,
        'accuracy_estimate': round((1 - mismatches/total)*100, 2) if total > 0 else None
    }


def export_all_feedback():
    """Экспорт всех отзывов в CSV и JSON"""
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query("SELECT * FROM feedbacks ORDER BY timestamp DESC", conn)
    conn.close()
    
    if not df.empty:
        df.to_csv(OUTPUT_DIR / 'feedback_export.csv', index=False)
        df.to_json(OUTPUT_DIR / 'feedback_export.json', orient='records', indent=2)
        print(f"Экспортировано {len(df)} отзывов")
    else:
        print("Нет отзывов для экспорта")
    
    return df


def export_misclassified():
    """Экспорт ошибочных предсказаний"""
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query('''
        SELECT id, url, model_verdict, user_verdict, user_comment, timestamp
        FROM feedbacks
        WHERE model_verdict != user_verdict AND user_verdict != 'other'
        ORDER BY timestamp DESC
    ''', conn)
    conn.close()
    
    if not df.empty:
        df.to_csv(OUTPUT_DIR / 'misclassified_urls.csv', index=False)
        print(f"Найдено {len(df)} ошибочных предсказаний")
    else:
        print("Нет ошибочных предсказаний")
    
    return df


def export_new_examples():
    """Экспорт новых примеров для дообучения модели"""
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query('''
        SELECT DISTINCT url, user_verdict
        FROM feedbacks
        WHERE user_verdict IN ('dangerous', 'safe')
        ORDER BY timestamp DESC
    ''', conn)
    conn.close()
    
    if df.empty:
        print("Нет новых примеров для обучения")
        return pd.DataFrame()
    
    # Конвертируем вердикты в числа для ML
    df['label'] = df['user_verdict'].map({
        'dangerous': 1,
        'safe': 0
    })
    
    # Убираем строки с неопределёнными метками
    df = df.dropna(subset=['label'])
    df['label'] = df['label'].astype(int)
    
    # Сохраняем только нужные колонки
    result = df[['url', 'label']]
    result.to_csv(OUTPUT_DIR / 'new_training_examples.csv', index=False)
    print(f"Найдено {len(result)} новых примеров для обучения")
    
    return result


def clear_database():
    """Полностью очищает БД (удаляет все записи)"""
    print("\nОЧИСТКА БАЗЫ ДАННЫХ")
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Считаем сколько записей было
    cursor.execute('SELECT COUNT(*) FROM feedbacks')
    before = cursor.fetchone()[0]
    
    # Удаляем все записи
    cursor.execute('DELETE FROM feedbacks')
    
    # Сбрасываем автоинкремент
    cursor.execute('DELETE FROM sqlite_sequence WHERE name="feedbacks"')
    
    conn.commit()
    conn.close()
    
    print(f"Удалено записей: {before}")
    
    # Оптимизируем БД
    if before > 0:
        conn = sqlite3.connect(DB_PATH)
        conn.execute('VACUUM')
        conn.close()
        print(f"БД оптимизирована")


# ОСНОВНОЙ ЗАПУСК 
if __name__ == '__main__':
    print("ЭКСПОРТ ОТЗЫВОВ ИЗ БД")
    
    # 1. Статистика
    print("\nСТАТИСТИКА:")
    stats = get_stats()
    for key, value in stats.items():
        if key != 'verdict_distribution':
            print(f"   {key}: {value}")
    
    if stats['verdict_distribution']:
        print(f"   verdict_distribution: {stats['verdict_distribution']}")
    
    # 2. Экспорт всех отзывов
    print("\nЭКСПОРТ ВСЕХ ОТЗЫВОВ:")
    export_all_feedback()
    
    # 3. Экспорт ошибочных предсказаний
    print("\nЭКСПОРТ ОШИБОЧНЫХ ПРЕДСКАЗАНИЙ:")
    export_misclassified()
    
    # 4. Экспорт новых примеров для обучения
    print("\nЭКСПОРТ ДЛЯ ОБУЧЕНИЯ:")
    export_new_examples()
    
    # 5. ОЧИСТКА БД
    clear_database()
    
    print("ЭКСПОРТ ЗАВЕРШЁН!")
    print("\nСозданные файлы:")
    print("   • data/feedback_export.csv - все отзывы")
    print("   • data/feedback_export.json - все отзывы (JSON)")
    print("   • data/misclassified_urls.csv - ошибки модели")
    print("   • data/new_training_examples.csv - для дообучения")
    print("\nБД полностью очищена, готова к новым отзывам!")