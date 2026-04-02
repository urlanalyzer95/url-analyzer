import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier

# Функция нормализации URL
def normalize_url(url):
    return url.lower().rstrip('/')

# Загружаем датасет признаков
df = pd.read_csv('data/processed/url_dataset_features.csv')

# Добавляем нормализованную колонку для поиска
df['url_norm'] = df['url'].apply(normalize_url)

# Признаки (исключаем url, label и url_norm)
X = df.drop(columns=['url', 'label', 'url_norm'])
y = df['label']

# Обучение модели
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X, y)

# Сохранение модели
joblib.dump(model, 'ml/model.pkl')

print("✅ Модель обучена и сохранена")
