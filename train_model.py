import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

# 1. Загружаем данные
df = pd.read_csv('data/processed/url_dataset_features.csv')

# 2. Разделяем
X = df.drop(columns=['url', 'label'])
y = df['label']

# 3. train/test split (важно для оценки)
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# safe_urls
safe_urls = [
    'https://google.com',
    'https://yandex.ru',
    'https://github.com',
    'https://stackoverflow.com'
]

from ml.features import extract_features

safe_features = [extract_features(url) for url in safe_urls]

import pandas as pd

safe_df = pd.DataFrame(safe_features, columns=df.drop(columns=['url', 'label']).columns)
safe_df['label'] = 0
safe_df['url'] = safe_urls

# Добавляем к датасету
df = pd.concat([df, safe_df], ignore_index=True)

# 4. Обучаем модель
model = RandomForestClassifier(
    n_estimators=150,
    max_depth=20,
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)

# 5. Проверяем точность
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)

print(f"Accuracy: {accuracy:.4f}")

# 6. Сохраняем модель
joblib.dump(model, 'ml/model.pkl')

print("Модель сохранена в ml/model.pkl")


