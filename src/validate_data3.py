import pandas as pd
import numpy as np

print("ПРОВЕРКА КАЧЕСТВА ДАННЫХ...")

df = pd.read_csv('data/processed/url_dataset_features.csv')

print(f"\nОБЩАЯ ИНФОРМАЦИЯ:")
print(f"   Записей: {len(df)}")
print(f"   Колонок: {len(df.columns)}")

print(f"\nПРОВЕРКА НА ПРОПУСКИ:")
missing = df.isnull().sum()
if missing.sum() == 0:
    print("   Пропусков нет")
else:
    print(f"   Найдено пропусков:\n{missing[missing > 0]}")

print(f"\nПРОВЕРКА НА ДУБЛИКАТЫ:")
duplicates = df.duplicated(subset=['url']).sum()
print(f"   Дубликатов URL: {duplicates}")

print(f"\nПРОВЕРКА ЛЕЙБЛОВ:")
print(f"   Уникальные значения: {df['label'].unique()}")
print(f"   Мин: {df['label'].min()}, Макс: {df['label'].max()}")

print(f"\nПРОВЕРКА ПРИЗНАКОВ:")
feature_cols = [col for col in df.columns if col not in ['url', 'label']]
for col in feature_cols[:5]:  # Первые 5 признаков
    print(f"   {col}: min={df[col].min():.2f}, max={df[col].max():.2f}, mean={df[col].mean():.2f}")

print("\nПРОВЕРКА ЗАВЕРШЕНА!")