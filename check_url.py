import pandas as pd

# Проверяем в исходном датасете
try:
    df = pd.read_csv('data/raw/url_dataset.csv')
    result = df[df['url'].str.contains('educatingwellness', na=False)]
    print(f'В raw/url_dataset.csv: {len(result)}')
    if len(result) > 0:
        print(result[['url', 'type']])
except Exception as e:
    print(f'Ошибка: {e}')

print()

# Проверяем в признаках
try:
    df = pd.read_csv('data/processed/url_dataset_features.csv')
    result = df[df['url'].str.contains('educatingwellness', na=False)]
    print(f'В features.csv: {len(result)}')
    if len(result) > 0:
        print(result[['url', 'label']])
except Exception as e:
    print(f'Ошибка: {e}')