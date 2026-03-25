import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from ml.features import extract_features
import os

# Загрузка датасета
print("Загрузка датасета...")
df = pd.read_csv('data/raw/url_dataset.csv', nrows=50000)

# Извлечение признаков через ту же функцию, что в server.py
print("Извлечение признаков...")
X = df['url'].apply(extract_features).tolist()
y = df['label']

# Обучение модели
print("Обучение модели...")
model = RandomForestClassifier(
    n_estimators=50,
    max_depth=10,
    min_samples_split=5,
    min_samples_leaf=2,
    random_state=42
)
model.fit(X, y)

# Сохранение модели
os.makedirs('ml', exist_ok=True)
joblib.dump(model, 'ml/model.pkl', compress=3)

print("Модель обучена и сохранена")
