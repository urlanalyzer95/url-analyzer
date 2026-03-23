import pandas as pd
import re
import json
import os
from pathlib import Path
from urllib.parse import urlparse
from datetime import datetime

# Правильные пути

# Автоматическое определение путей относительно этого файла
BASE_DIR = Path(__file__).parent.parent  # URL-ANALYZER/
raw_folder = BASE_DIR / 'data' / 'raw'
processed_folder = BASE_DIR / 'data' / 'processed'

# Создаём папки, если их нет
os.makedirs(raw_folder, exist_ok=True)
os.makedirs(processed_folder, exist_ok=True)


def clean_url_dataset(df):
    # 1. Удалить дубликаты по URL
    url_col = 'url' if 'url' in df.columns else 'URL'
    if url_col in df.columns:
        df = df.drop_duplicates(subset=[url_col])
    
    # 2. Удалить строки с пустыми значениями
    df = df.dropna()
    
    # 3. Проверить корректность URL + очистка
    if url_col in df.columns:
        # Очистка пробелов и нижний регистр
        df[url_col] = df[url_col].astype(str).str.strip().str.lower()
        df = df[df[url_col] != '']
        df = df[df[url_col] != 'nan']
        
        # Валидация через urlparse (надёжнее regex)
        def is_valid_url(url):
            try:
                parsed = urlparse(url)
                return bool(parsed.scheme and parsed.netloc)
            except:
                return False
        
        df = df[df[url_col].apply(is_valid_url)]
    
    # 4. Унифицировать названия колонок + конвертация меток
    df = df.rename(columns={
        'URL': 'url', 'Url': 'url',
        'type': 'label', 'class': 'label', 'classification': 'label'
    })
    
    # Конвертация меток в числа
    if 'label' in df.columns:
        df['label'] = df['label'].astype(str).str.lower().str.strip()
        label_map = {
            'legitimate': 0, 'safe': 0, 'good': 0,
            'phishing': 1, 'malicious': 1, 'bad': 1
        }
        df['label'] = df['label'].map(label_map)
        df = df[df['label'].notna()]
        df['label'] = df['label'].astype(int)
    
    return df

# Балансировка классов (обязательно для ML)

def balance_classes(df, label_col='label', random_state=42):
    if label_col not in df.columns:
        return df
    
    counts = df[label_col].value_counts()
    if len(counts) < 2:
        return df
    
    print(f"   До балансировки: {counts.to_dict()}")
    
    min_count = counts.min()
    df_balanced = pd.concat([
        df[df[label_col] == cls].sample(min_count, random_state=random_state)
        for cls in df[label_col].unique()
    ], ignore_index=True)
    
    print(f"   После балансировки: {len(df_balanced):,} строк")
    return df_balanced

# Извлечение признаков 

def extract_features(df, url_col='url'):
    """Превращает URL в числовые признаки для ML"""
    if url_col not in df.columns:
        return df
    
    features = pd.DataFrame(index=df.index)
    
    # Базовые признаки
    features['url_length'] = df[url_col].str.len()
    features['num_dots'] = df[url_col].str.count(r'\.')
    features['num_hyphens'] = df[url_col].str.count(r'-')
    features['num_slashes'] = df[url_col].str.count(r'/')
    features['num_params'] = df[url_col].str.count(r'[?&]')
    
    # Безопасность
    features['has_ip'] = df[url_col].str.contains(
        r'\d{1,3}(?:\.\d{1,3}){3}', regex=True, na=False
    ).astype(int)
    features['has_https'] = df[url_col].str.startswith('https', na=False).astype(int)
    
    # Подозрительные слова
    for word in ['login', 'verify', 'account', 'cp.php', 'admin']:
        features[f'has_{word}'] = df[url_col].str.contains(
            word, case=False, na=False
        ).astype(int)
    
    # Сокращатели
    features['is_shortened'] = df[url_col].str.contains(
        'bit.ly|goo.gl|tinyurl', case=False, na=False
    ).astype(int)
    
    # Структура
    features['domain_length'] = df[url_col].apply(
        lambda x: len(urlparse(str(x)).netloc)
    )
    
    # Целевая переменная и URL
    if 'label' in df.columns:
        features['label'] = df['label']
    features['url'] = df[url_col]
    
    return features

# Сохранение с метаданными

def save_with_metadata(df_features, output_path, original_name):
    # Сохраняем CSV
    df_features.to_csv(output_path, index=False, encoding='utf-8')
    
    # Сохраняем метаданные (для Роль 1)
    metadata = {
        'source_file': original_name,
        'feature_columns': [c for c in df_features.columns if c not in ['url', 'label']],
        'label_mapping': {'legitimate': 0, 'phishing': 1},
        'total_samples': len(df_features),
        'generated_at': datetime.now().isoformat()
    }
    
    with open(output_path.with_suffix('.json'), 'w', encoding='utf-8') as f:
        json.dump(metadata, f, indent=2, ensure_ascii=False)
    
    print(f"   Сохранено: {Path(output_path).name}")


# ОСНОВНОЙ ЦИКЛ

if __name__ == '__main__':
    print("Обработка датасетов URL-ANALYZER\n")
    
    # Ищем CSV файлы
    csv_files = list(Path(raw_folder).glob('*.csv'))
    print(f"Найдено файлов: {len(csv_files)}\n")
    
    if not csv_files:
        print("Нет CSV файлов в data/raw/")
        exit(1)
    
    for file_path in csv_files:
        print(f"{file_path.name}")
        
        try:
            # Загрузка
            df = pd.read_csv(file_path, encoding='utf-8', on_bad_lines='skip')
            print(f"   Загружено: {len(df):,} строк")
            
            # Очистка
            df_clean = clean_url_dataset(df)
            print(f"   После очистки: {len(df_clean):,} строк")
            
            # Балансировка
            df_clean = balance_classes(df_clean)
            
            # Признаки
            df_features = extract_features(df_clean)
            
            # Сохранение
            output_path = Path(processed_folder) / f"{file_path.stem}_features.csv"
            save_with_metadata(df_features, output_path, file_path.name)
            
            # Статистика
            if 'label' in df_clean.columns:
                dist = df_clean['label'].value_counts().to_dict()
                print(f"   Классы: 0={dist.get(0,0):,}, 1={dist.get(1,0):,}")
            
            print()
            
        except Exception as e:
            print(f"   Ошибка: {e}")
    
    print("Готово! Результаты в data/processed/")