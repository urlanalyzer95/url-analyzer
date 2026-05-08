"""
Поиск URL в датасете
Роль 2: Data-инженер
"""

import pandas as pd
from pathlib import Path

# Пути к датасетам
DATASET_PATHS = [
    Path('data/processed/url_dataset_features.csv'),
    Path('data/processed/url_dataset_features_v2.csv'),
]

# URL для поиска
SEARCH_URL = 'https://google.com'

print("=" * 60)
print(f"🔍 ПОИСК: {SEARCH_URL}")
print("=" * 60)

# Пробуем найти датасет
df = None
dataset_file = None

for path in DATASET_PATHS:
    if path.exists():
        df = pd.read_csv(path)
        dataset_file = path
        print(f"✅ Загружен: {dataset_file}")
        break

if df is None:
    print("❌ Датасет не найден!")
    print("💡 Запусти сначала prepare_dataset.py")
    exit(1)

print(f"\n📊 Всего записей: {len(df):,}")

# 1. Точный поиск
print(f"\n🎯 ТОЧНЫЙ ПОИСК: '{SEARCH_URL}'")
exact_match = df[df['url'] == SEARCH_URL]

if not exact_match.empty:
    print(f"✅ Найдено: {len(exact_match)} совпадений")
    
    for idx, row in exact_match.iterrows():
        print(f"\n{'─' * 60}")
        print(f"🔗 URL: {row['url']}")
        print(f"🏷️  Label: {row['label']} ({'🟢 БЕЗОПАСНО' if row['label'] == 0 else '🔴 ОПАСНО'})")
        print(f"\n📐 ПРИЗНАКИ:")
        for col in df.columns:
            if col not in ['url', 'label']:
                print(f"   • {col:20s} = {row[col]}")
else:
    print("❌ Точное совпадение не найдено")

# 2. Поиск по подстроке "google"
print(f"\n🔎 ПОИСК ПО ПОДСТРОКЕ: 'google'")
google_matches = df[df['url'].str.contains('google', case=False, na=False)]

if not google_matches.empty:
    print(f"✅ Найдено: {len(google_matches):,} ссылок с 'google'")
    
    print(f"\n📋 ПЕРВЫЕ 10 РЕЗУЛЬТАТОВ:")
    print("-" * 60)
    for idx, row in google_matches.head(10).iterrows():
        label = "🟢" if row['label'] == 0 else "🔴"
        print(f"{label} {row['label']} | {row['url'][:60]}")
    
    # Статистика
    safe_count = (google_matches['label'] == 0).sum()
    danger_count = (google_matches['label'] == 1).sum()
    print(f"\n📊 СТАТИСТИКА:")
    print(f"   • Безопасных (0): {safe_count} ({safe_count/len(google_matches)*100:.1f}%)")
    print(f"   • Опасных (1): {danger_count} ({danger_count/len(google_matches)*100:.1f}%)")
else:
    print("❌ Ссылки с 'google' не найдены")

# 3. Сохранить результаты (опционально)

print("\n" + "=" * 60)
print("✅ ПОИСК ЗАВЕРШЁН")
print("=" * 60)