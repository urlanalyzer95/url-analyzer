import pandas as pd
import numpy as np
from pathlib import Path
import sys

# Добавляем путь к ml папке
sys.path.append(str(Path(__file__).parent.parent / 'ml'))
from features import extract_features

# Пути
DATA_DIR = Path('data/processed')
DATA_DIR.mkdir(parents=True, exist_ok=True)

OLD_DATASET = 'data/processed/url_dataset_features.csv'
NEW_EXAMPLES = 'data/new_training_examples.csv'
OUTPUT_DATASET = 'data/processed/url_dataset_features_v2.csv'


def load_main_dataset():
    # Загрузка основного датасета
    if Path(OLD_DATASET).exists():
        df = pd.read_csv(OLD_DATASET)
        print(f"📁 Основной датасет: {len(df)} записей")
        return df
    else:
        print(f"⚠️ Основной датасет не найден: {OLD_DATASET}")
        return pd.DataFrame()


def load_new_examples():
    # Загрузка новых примеров из отзывов
    if Path(NEW_EXAMPLES).exists():
        df = pd.read_csv(NEW_EXAMPLES)
        df = df[['url', 'label']]
        print(f"📁 Новые примеры из отзывов: {len(df)} записей")
        return df
    else:
        print("⚠️ Нет новых примеров из отзывов")
        return pd.DataFrame(columns=['url', 'label'])


def extract_features_for_urls(df, feature_cols):
    # Извлечение признаков для новых URL
    print("\n⚙️ Извлечение признаков для новых URL...")
    
    new_features = []
    new_labels = []
    
    for idx, row in df.iterrows():
        url = row['url']
        label = row['label']
        
        features = extract_features(url)
        new_features.append(features)
        new_labels.append(label)
    
    # Создаём DataFrame с признаками
    feedback_features_df = pd.DataFrame(new_features, columns=feature_cols)
    feedback_features_df['url'] = df['url'].values
    feedback_features_df['label'] = df['label'].values
    
    print(f"   ✅ Извлечено признаков: {feedback_features_df.shape}")
    return feedback_features_df


def prepare_dataset():
    """Основная функция подготовки датасета"""
    print("\n" + "="*50)
    print("🔄 ПОДГОТОВКА НОВОГО ДАТАСЕТА")
    print("="*50)
    
    # 1. Загружаем основной датасет
    main_df = load_main_dataset()
    if main_df.empty:
        print("❌ Нет основного датасета, создаём новый...")
        main_df = pd.DataFrame()
    
    # 2. Загружаем новые примеры
    feedback_df = load_new_examples()
    
    if feedback_df.empty:
        print("\n Нет новых данных, используем старый датасет")
        main_df.to_csv(OUTPUT_DATASET, index=False)
        print(f"   💾 Сохранён: {OUTPUT_DATASET}")
        return
    
    # 3. Определяем колонки признаков
    if not main_df.empty:
        feature_cols = [col for col in main_df.columns if col not in ['url', 'label']]
    else:
        # Если основного датасета нет, создаём пустой с правильными колонками
        # Извлекаем признаки для одного URL, чтобы узнать колонки
        test_features = extract_features("https://example.com")
        feature_cols = [f'feature_{i}' for i in range(len(test_features))]
        main_df = pd.DataFrame(columns=['url', 'label'] + feature_cols)
    
    # 4. Извлекаем признаки для новых URL
    feedback_features_df = extract_features_for_urls(feedback_df, feature_cols)
    
    # 5. Объединяем датасеты
    combined_df = pd.concat([main_df, feedback_features_df], ignore_index=True)
    
    # 6. Удаляем дубликаты
    before_dedup = len(combined_df)
    combined_df = combined_df.drop_duplicates(subset=['url'], keep='last')
    after_dedup = len(combined_df)
    print(f"\n🗑️ Удалено дубликатов: {before_dedup - after_dedup}")
    
    # 7. Проверяем баланс классов
    if 'label' in combined_df.columns:
        print(f"\n📊 РАСПРЕДЕЛЕНИЕ КЛАССОВ:")
        print(f"   Безопасных (0): {(combined_df['label'] == 0).sum()}")
        print(f"   Опасных (1): {(combined_df['label'] == 1).sum()}")
        print(f"   Всего: {len(combined_df)}")
    
    # 8. Сохраняем новый датасет
    combined_df.to_csv(OUTPUT_DATASET, index=False)
    print(f"\n✅ НОВЫЙ ДАТАСЕТ СОХРАНЁН:")
    print(f"   {OUTPUT_DATASET}")
    print(f"   Размер: {len(combined_df)} записей")


# ОСНОВНОЙ ЗАПУСК 
if __name__ == '__main__':
    prepare_dataset()
    print("\n✅ ПОДГОТОВКА ЗАВЕРШЕНА!")