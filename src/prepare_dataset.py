import pandas as pd
import sqlite3
import re
from pathlib import Path
from urllib.parse import urlparse

# Пути
DB_PATH = 'data/feedback.db'
DATASET_FILE = 'data/processed/url_dataset_features.csv'


def clean_feedback(df):
    """Очистка отзывов (копия логики из clean_data.py)"""
    # 1. Удалить дубликаты по URL
    df = df.drop_duplicates(subset=['url'])
    
    # 2. Удалить строки с пустыми значениями
    df = df.dropna()
    
    # 3. Очистка URL
    df['url'] = df['url'].astype(str).str.strip().str.lower()
    df = df[df['url'] != '']
    df = df[df['url'] != 'nan']
    
    # 4. Валидация URL
    def is_valid_url(url):
        try:
            parsed = urlparse(url)
            return bool(parsed.scheme and parsed.netloc)
        except:
            return False
    
    df = df[df['url'].apply(is_valid_url)]
    
    return df


def extract_features(df):
    """Извлечение признаков (копия логики из clean_data.py)"""
    features = pd.DataFrame(index=df.index)
    
    # Базовые признаки
    features['url_length'] = df['url'].str.len()
    features['num_dots'] = df['url'].str.count(r'\.')
    features['num_hyphens'] = df['url'].str.count(r'-')
    features['num_slashes'] = df['url'].str.count(r'/')
    features['num_params'] = df['url'].str.count(r'[?&]')
    
    # Безопасность
    features['has_ip'] = df['url'].str.contains(
        r'\d{1,3}(?:\.\d{1,3}){3}', regex=True, na=False
    ).astype(int)
    features['has_https'] = df['url'].str.startswith('https', na=False).astype(int)
    
    # Подозрительные слова
    for word in ['login', 'verify', 'account', 'cp.php', 'admin']:
        features[f'has_{word}'] = df['url'].str.contains(
            word, case=False, na=False
        ).astype(int)
    
    # Сокращатели
    features['is_shortened'] = df['url'].str.contains(
        'bit.ly|goo.gl|tinyurl', case=False, na=False
    ).astype(int)
    
    # Структура
    features['domain_length'] = df['url'].apply(
        lambda x: len(urlparse(str(x)).netloc)
    )
    
    # Целевая переменная и URL
    features['label'] = df['label']
    features['url'] = df['url']
    
    return features


def load_feedback_from_db():
    """Загружает ВСЕ отзывы из БД"""
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query('''
        SELECT DISTINCT url, user_verdict
        FROM feedbacks
        WHERE user_verdict IN ('dangerous', 'safe')
    ''', conn)
    conn.close()
    
    if df.empty:
        return pd.DataFrame()
    
    # Конвертируем метки
    df['label'] = df['user_verdict'].map({'dangerous': 1, 'safe': 0})
    df = df.dropna(subset=['label'])
    df['label'] = df['label'].astype(int)
    
    print(f"📁 Загружено отзывов из БД: {len(df)}")
    print(f"   Опасных (1): {(df['label'] == 1).sum()}")
    print(f"   Безопасных (0): {(df['label'] == 0).sum()}")
    
    return df[['url', 'label']]


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


def update_dataset():
    """Добавляет отзывы в датасет"""
    print("\n" + "="*50)
    print("🔄 ДОБАВЛЕНИЕ ОТЗЫВОВ В ДАТАСЕТ")
    print("="*50)
    
    # 1. Загружаем отзывы из БД
    feedback_df = load_feedback_from_db()
    
    if feedback_df.empty:
        print("\n⚠️ В БД нет отзывов для обработки")
        return
    
    # 2. Очистка отзывов
    print("\n🧹 Очистка URL...")
    feedback_clean = clean_feedback(feedback_df)
    print(f"   После очистки: {len(feedback_clean)} записей")
    
    # 3. Извлечение признаков
    print("\n⚙️ Извлечение признаков...")
    feedback_features = extract_features(feedback_clean)
    print(f"   Признаков: {len(feedback_features.columns) - 2}")  # -2 для url и label
    
    # 4. Загружаем существующий датасет
    if not Path(DATASET_FILE).exists():
        print(f"\n❌ ОШИБКА: Датасет не найден: {DATASET_FILE}")
        print("   Сначала запустите clean_data.py")
        return
    
    current_df = pd.read_csv(DATASET_FILE)
    current_count = len(current_df)
    print(f"\n📁 Существующий датасет: {current_count} записей")
    
    # 5. Объединяем
    updated_df = pd.concat([current_df, feedback_features], ignore_index=True)
    
    # 6. Удаляем дубликаты
    before_dedup = len(updated_df)
    updated_df = updated_df.drop_duplicates(subset=['url'], keep='last')
    after_dedup = len(updated_df)
    duplicates_removed = before_dedup - after_dedup
    
    # 7. Сохраняем
    updated_df.to_csv(DATASET_FILE, index=False)
    
    # 8. Статистика
    print(f"\n✅ ДАТАСЕТ ОБНОВЛЁН:")
    print(f"   Было: {current_count} записей")
    print(f"   Добавлено: {len(feedback_features)} записей")
    if duplicates_removed > 0:
        print(f"   Удалено дубликатов: {duplicates_removed}")
    print(f"   Стало: {after_dedup} записей")
    
    # 9. Распределение классов
    print(f"\n📊 РАСПРЕДЕЛЕНИЕ КЛАССОВ:")
    safe_count = (updated_df['label'] == 0).sum()
    dangerous_count = (updated_df['label'] == 1).sum()
    print(f"   Безопасных (0): {safe_count}")
    print(f"   Опасных (1): {dangerous_count}")
    
    if after_dedup > 0:
        ratio = dangerous_count / after_dedup * 100
        print(f"   Соотношение: {ratio:.1f}% опасных")
    
    # 10. Очищаем БД
    clear_database()
    
    print("\n" + "="*50)
    print("✅ ГОТОВО!")


if __name__ == '__main__':
    update_dataset()