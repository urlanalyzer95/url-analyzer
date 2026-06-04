import pandas as pd
import numpy as np
from pathlib import Path

print(" ПРОВЕРКА КАЧЕСТВА ДАННЫХ...")

# Путь
DATASET_FILE = Path('data/processed/url_dataset_features.csv')

if not DATASET_FILE.exists():
    print(f" Файл не найден: {DATASET_FILE}")
    print(" Запусти сначала clean_data.py или prepare_dataset.py")
    exit(1)

df = pd.read_csv(DATASET_FILE)

print(f"\n ОБЩАЯ ИНФОРМАЦИЯ:")
print(f"   Записей: {len(df):,}")
print(f"   Колонок: {len(df.columns)}")

print(f"\n ПРОВЕРКА НА ПРОПУСКИ:")
missing = df.isnull().sum()
if missing.sum() == 0:
    print("    Пропусков нет")
else:
    print(f"     Найдено пропусков:\n{missing[missing > 0]}")

print(f"\n ПРОВЕРКА НА ДУБЛИКАТЫ:")
duplicates = df.duplicated(subset=['url']).sum()
print(f"   Дубликатов URL: {duplicates:,}")

print(f"\n ПРОВЕРКА ЛЕЙБЛОВ:")
print(f"   Уникальные значения: {df['label'].unique()}")
print(f"   Мин: {df['label'].min()}, Макс: {df['label'].max()}")

print(f"\n ПРОВЕРКА ПРИЗНАКОВ:")
feature_cols = [col for col in df.columns if col not in ['url', 'label']]
for col in feature_cols[:5]:  # Первые 5 признаков
    print(f"   {col}: min={df[col].min():.2f}, max={df[col].max():.2f}, mean={df[col].mean():.2f}")

print(f"\n БАЛАНС КЛАССОВ:")
safe_count = (df['label'] == 0).sum()
danger_count = (df['label'] == 1).sum()
print(f"    Безопасных (0): {safe_count:,} ({safe_count/len(df)*100:.1f}%)")
print(f"    Опасных (1): {danger_count:,} ({danger_count/len(df)*100:.1f}%)")

print("\n ПРОВЕРКА ЗАВЕРШЕНА!")