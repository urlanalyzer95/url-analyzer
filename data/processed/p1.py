import pandas as pd
import numpy as np

# Загружаем ваш датасет
# df = pd.read_csv('url_dataset_100k.csv')

# import pandas as pd

# Укажите ЗДЕСЬ полный путь к вашему файлу
# file_path = r'C:\Users\1135k\OneDrive\Desktop\url\url-analyzer\data\processed\url_dataset_features.csv'
file_path = r'C:\Users\1135k\OneDrive\Desktop\url\url-analyzer\data\processed\url_dataset_features_v2.csv'
df = pd.read_csv(file_path)
print(f"Загружено: {len(df)}")

# Проверяем, есть ли в датасете проблемные URL
problematic_urls = ['wikipedia.org', 'vk.com', 'confirm-identity.net']

for url in problematic_urls:
    # Ищем частичное совпадение
    matches = df[df['url'].str.contains(url, case=False, na=False)]
    if len(matches) > 0:
        print(f"\n{url}:")
        print(matches[['url', 'label']].head())
        print(f"Метка в датасете: {matches['label'].iloc[0] if len(matches) > 0 else 'НЕТ'}")
    else:
        print(f"\n{url}: НЕ НАЙДЕН в датасете")