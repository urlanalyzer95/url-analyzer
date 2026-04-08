import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from ml.features import extract_features

# 1. Загружаем данные
df = pd.read_csv('data/processed/url_dataset_features.csv')

# 2. Добавляем safe URLs
safe_urls = [
    'https://google.com',
    'https://yandex.ru',
    'https://github.com',
    'https://stackoverflow.com',
    'https://vk.com',
    'https://wikipedia.org',
    'https://youtube.com',
    'https://instagram.com',
    'https://facebook.com',
    'https://twitter.com',
    'https://amazon.com',
    'https://apple.com',
    'https://microsoft.com',
]

safe_features = [extract_features(url) for url in safe_urls]

feature_cols = [c for c in df.columns if c not in ['url', 'label']]

safe_df = pd.DataFrame(safe_features, columns=feature_cols)
safe_df['label'] = 0
safe_df['url'] = safe_urls

df = pd.concat([df, safe_df], ignore_index=True)

# 3. Пересоздаём X и y (ВАЖНО!)
X = df[feature_cols]
y = df['label']

# 4. Делим
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# 5. Обучаем
model = RandomForestClassifier(
    n_estimators=150,
    max_depth=10,
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)

# 6. Проверка
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)

print(f"Accuracy: {accuracy:.4f}")

# 7. Сохраняем
joblib.dump(model, 'ml/model.pkl')

print("Модель сохранена")
