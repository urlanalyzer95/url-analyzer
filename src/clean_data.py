import pandas as pd
import re
import json
import os
from pathlib import Path
from urllib.parse import urlparse
from datetime import datetime

# Пути
BASE_DIR = Path(__file__).parent.parent
raw_folder = BASE_DIR / 'data' / 'raw'
processed_folder = BASE_DIR / 'data' / 'processed'

os.makedirs(raw_folder, exist_ok=True)
os.makedirs(processed_folder, exist_ok=True)

def clean_url_dataset(df):
    """Очистка датасета: удаление дубликатов по URL, валидация"""
    url_col = 'url' if 'url' in df.columns else 'URL'
    
    # 1. Удаляем дубликаты по URL
    if url_col in df.columns:
        before = len(df)
        df = df.drop_duplicates(subset=[url_col])
        print(f"   Удалено дубликатов по URL: {before - len(df)}")
    
    # 2. Удаляем пустые строки
    df = df.dropna()
    
    # 3. Валидация URL
    if url_col in df.columns:
        df[url_col] = df[url_col].astype(str).str.strip().str.lower()
        df = df[df[url_col] != '']
        df = df[df[url_col] != 'nan']
        
        def is_valid_url(url):
            try:
                parsed = urlparse(url)
                return bool(parsed.scheme and parsed.netloc)
            except:
                return False
        
        df = df[df[url_col].apply(is_valid_url)]
    
    # 4. Унификация колонок и меток
    df = df.rename(columns={
        'URL': 'url', 'Url': 'url',
        'type': 'label', 'class': 'label', 'classification': 'label'
    })
    
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

def extract_features(df, url_col='url'):
    """Извлечение признаков из URL"""
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
    
    # Домен
    features['domain_length'] = df[url_col].apply(
        lambda x: len(urlparse(str(x)).netloc)
    )
    
    # URL и label
    if 'label' in df.columns:
        features['label'] = df['label']
    features['url'] = df[url_col]
    
    return features

def balance_classes(df, label_col='label', random_state=42):
    """Балансировка классов"""
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

def save_with_metadata(df_features, output_path, original_name):
    """Сохранение с метаданными"""
    df_features.to_csv(output_path, index=False, encoding='utf-8')
    
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
    
    csv_files = list(Path(raw_folder).glob('*.csv'))
    print(f"Найдено файлов: {len(csv_files)}\n")
    
    if not csv_files:
        print("Нет CSV файлов в data/raw/")
        exit(1)
    
    for file_path in csv_files:
        print(f"{file_path.name}")
        
        try:
            # 1. Загрузка
            df = pd.read_csv(file_path, encoding='utf-8', on_bad_lines='skip')
            print(f"   Загружено: {len(df):,} строк")
            
            # 2. Очистка (удаляет дубликаты по URL)
            df_clean = clean_url_dataset(df)
            print(f"   После очистки: {len(df_clean):,} строк")
            
            # ✅ 3. ИЗВЛЕЧЕНИЕ ПРИЗНАКОВ (ПЕРЕНОСИМ СЮДА!)
            df_features = extract_features(df_clean)
            print(f"   Извлечено признаков: {len(df_features.columns)}")
            
            # ✅ 4. УДАЛЕНИЕ ДУБЛИКАТОВ ПО ПРИЗНАКАМ (ПЕРЕД БАЛАНСИРОВКОЙ!)
            feature_cols_only = [col for col in df_features.columns if col not in ['url', 'label']]
            before = len(df_features)
            df_features = df_features.drop_duplicates(subset=feature_cols_only, keep='first')
            after = len(df_features)
            print(f"\n   🗑️ Удалено дубликатов по признакам: {before - after:,} ({(before-after)/before*100:.1f}%)")
            print(f"   Итого уникальных комбинаций признаков: {after:,}")
            
            # ✅ 5. БАЛАНСИРОВКА (ПОСЛЕ удаления дубликатов!)
            df_balanced = balance_classes(df_features)
            
            # 6. Сохранение
            output_path = Path(processed_folder) / f"{file_path.stem}_features4.csv"
            save_with_metadata(df_balanced, output_path, file_path.name)
            
            # Статистика
            if 'label' in df_balanced.columns:
                dist = df_balanced['label'].value_counts().to_dict()
                print(f"\n   📊 Классы: 0={dist.get(0,0):,}, 1={dist.get(1,0):,}")
                print(f"   📈 Баланс: {dist.get(0,0)/dist.get(1,1):.2f}:1")
            
            print()
            
        except Exception as e:
            print(f"   ❌ Ошибка: {e}")
            import traceback
            traceback.print_exc()
    
    print("Готово! Результаты в data/processed/")