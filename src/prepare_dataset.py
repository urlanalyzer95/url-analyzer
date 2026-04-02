import pandas as pd
import numpy as np
from pathlib import Path
import sys
# sys.path.append('ml')

ROOT_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT_DIR))

# Импортируем из ml.features
from ml.features import extract_features

# sys.path.append(str(Path(__file__).parent.parent / 'ml'))
# from features import extract_features

print("🔄 ПОДГОТОВКА НОВОГО ДАТАСЕТА...")

# 1. Загружаем основной датасет
main_df = pd.read_csv('data/processed/url_dataset_features.csv')
print(f"📁 Основной датасет: {len(main_df)} записей")

# 2. Загружаем новые примеры из отзывов
try:
    feedback_df = pd.read_csv('data/new_training_examples.csv')
    feedback_df = feedback_df[['url', 'label']]  # Только нужные колонки
    print(f"📁 Новые примеры из отзывов: {len(feedback_df)} записей")
except:
    print("⚠️  Нет новых примеров из отзывов")
    feedback_df = pd.DataFrame(columns=['url', 'label'])

# 3. Извлекаем признаки для новых URL
if not feedback_df.empty:
    print("\n  Извлечение признаков для новых URL...")
    
    new_features = []
    new_labels = []
    
    for idx, row in feedback_df.iterrows():
        url = row['url']
        label = row['label']
        
        # Извлекаем признаки
        features = extract_features(url)
        new_features.append(features)
        new_labels.append(label)
    
    # Создаём DataFrame с признаками
    # ВАЖНО: должны быть те же колонки, что в основном датасете
    feature_cols = [col for col in main_df.columns if col not in ['url', 'label']]
    
    feedback_features_df = pd.DataFrame(new_features, columns=feature_cols)
    feedback_features_df['url'] = feedback_df['url'].values
    feedback_features_df['label'] = feedback_df['label'].values
    
    print(f"✅ Извлечено признаков: {feedback_features_df.shape}")
    
    # 4. Объединяем датасеты
    combined_df = pd.concat([main_df, feedback_features_df], ignore_index=True)
    
    # 5. Удаляем дубликаты
    before_dedup = len(combined_df)
    combined_df = combined_df.drop_duplicates(subset=['url'], keep='last')
    after_dedup = len(combined_df)
    print(f"\n  Удалено дубликатов: {before_dedup - after_dedup}")
    
    # 6. Проверяем баланс классов
    print(f"\n📊 РАСПРЕДЕЛЕНИЕ КЛАССОВ:")
    print(f"   Безопасных (0): {(combined_df['label'] == 0).sum()}")
    print(f"   Опасных (1): {(combined_df['label'] == 1).sum()}")
    print(f"   Всего: {len(combined_df)}")
    
    # 7. Сохраняем новый датасет
    combined_df.to_csv('data/processed/url_dataset_features_v2.csv', index=False)
    print(f"\n✅ НОВЫЙ ДАТАСЕТ СОХРАНЁН:")
    print(f"   data/processed/url_dataset_features_v2.csv")
    print(f"   Размер: {len(combined_df)} записей")
    
else:
    print("⚠️  Нет новых данных, используем старый датасет")
    main_df.to_csv('data/processed/url_dataset_features_v2.csv', index=False)

print("\n✅ ПОДГОТОВКА ЗАВЕРШЕНА!")