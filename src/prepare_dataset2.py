import pandas as pd
from pathlib import Path
import sys

sys.path.append(str(Path(__file__).parent.parent / 'ml'))
from features import extract_features, feature_cols

# Пути
DATASET_FILE = 'data/processed/url_dataset_features.csv'
NEW_EXAMPLES = 'data/new_training_examples.csv'


def update_dataset():
    print("ДОБАВЛЕНИЕ НОВЫХ ОТЗЫВОВ В ДАТАСЕТ")
    
    # 1. Загружаем новые отзывы
    if not Path(NEW_EXAMPLES).exists():
        print("Нет новых отзывов для добавления")
        return
    
    new_df = pd.read_csv(NEW_EXAMPLES)
    print(f"Новых отзывов: {len(new_df)}")
    
    # 2. Загружаем существующий датасет
    if not Path(DATASET_FILE).exists():
        print(f"Датасет не найден: {DATASET_FILE}")
        return
    
    current_df = pd.read_csv(DATASET_FILE)
    current_count = len(current_df)
    print(f"Текущий датасет: {current_count} записей")
    
    # 3. Извлекаем признаки для новых URL
    print("\nИзвлечение признаков...")
    
    all_features = []
    for idx, row in new_df.iterrows():
        url = row['url']
        label = row['label']
        
        # extract_features возвращает DataFrame, берём первую строку как список
        features_df = extract_features(url)
        features_list = features_df.iloc[0].tolist()
        
        all_features.append(features_list)
        print(f"   {idx+1}/{len(new_df)}: {url[:50]}... -> {len(features_list)} признаков")
    
    # 4. Создаём DataFrame с признаками
    new_features_df = pd.DataFrame(all_features, columns=feature_cols)
    new_features_df['url'] = new_df['url'].values
    new_features_df['label'] = new_df['label'].values
    
    # 5. Добавляем в датасет
    updated_df = pd.concat([current_df, new_features_df], ignore_index=True)
    updated_df = updated_df.drop_duplicates(subset=['url'], keep='last')
    
    # 6. Сохраняем
    updated_df.to_csv(DATASET_FILE, index=False)
    
    print(f"\nДАТАСЕТ ОБНОВЛЁН:")
    print(f"   Было: {current_count}")
    print(f"   Добавлено: {len(new_df)}")
    print(f"   Стало: {len(updated_df)}")
    
    # 7. Удаляем CSV с отзывами
    Path(NEW_EXAMPLES).unlink()
    print(f"\nУдалён {NEW_EXAMPLES}")


if __name__ == '__main__':
    update_dataset()