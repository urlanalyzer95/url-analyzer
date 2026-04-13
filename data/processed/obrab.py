# import pandas as pd

# print("Загрузка данных...")
# # df = pd.read_csv('url_dataset_features.csv')
# df = pd.read_csv('data\processed\url_dataset_features.csv')


import pandas as pd

# Укажите ЗДЕСЬ полный путь к вашему файлу
file_path = r'C:\Users\1135k\OneDrive\Desktop\url\url-analyzer\data\processed\url_dataset_features.csv'

df = pd.read_csv(file_path)
print(f"Загружено: {len(df)}")

print(f"Загружено записей: {len(df)}")
print(f"Безопасных: {(df['label'] == 0).sum()}")
print(f"Фишинговых: {(df['label'] == 1).sum()}")

# Берем по 50000
safe_sample = df[df['label'] == 0].sample(50000, random_state=42)
phish_sample = df[df['label'] == 1].sample(50000, random_state=42)

# Объединяем и перемешиваем
df_100k = pd.concat([safe_sample, phish_sample]).sample(frac=1, random_state=42).reset_index(drop=True)

# Сохраняем
df_100k.to_csv('url_dataset_100k.csv', index=False)

print(f"\n✅ Готово! Сохранено {len(df_100k)} записей")
print(f"   Безопасных: {(df_100k['label'] == 0).sum()}")
print(f"   Фишинговых: {(df_100k['label'] == 1).sum()}")