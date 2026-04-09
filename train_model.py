import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
from ml.features import extract_features

print("Загрузка данных...")
df = pd.read_csv('data/processed/url_dataset_features.csv')
print(f"Исходный датасет: {len(df)} записей")

# Добавляем безопасные URL
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
    'https://reddit.com',
    'https://linkedin.com',
]

print(f"Добавляем {len(safe_urls)} доверенных URL...")
safe_features = [extract_features(url) for url in safe_urls]

feature_cols = [c for c in df.columns if c not in ['url', 'label']]

safe_df = pd.DataFrame(safe_features, columns=feature_cols)
safe_df['label'] = 0
safe_df['url'] = safe_urls

df = pd.concat([df, safe_df], ignore_index=True)
print(f"После добавления: {len(df)} записей")

# Создаём X и y
X = df[feature_cols]
y = df['label']

print(f"Признаков: {X.shape[1]}")
print(f"Распределение классов: 0={sum(y==0)}, 1={sum(y==1)}")

# Делим на обучающую и тестовую выборки
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# Обучаем модель
print("Обучение модели...")
model = RandomForestClassifier(
    n_estimators=150,
    max_depth=10,
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)

# Оценка
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)

print(f"\nAccuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")
print("\nОтчёт по классам:")
print(classification_report(y_test, y_pred))

# Проверка на доверенных доменах
print("\nПроверка доверенных доменов:")
test_urls = [
    'https://google.com',
    'https://wikipedia.org',
    'https://vk.com',
    'https://yandex.ru',
    'https://github.com',
]

for url in test_urls:
    features = extract_features(url)
    proba = model.predict_proba([features])[0][1]
    if proba < 0.3:
        verdict = "Безопасно"
    elif proba > 0.7:
        verdict = "Опасно"
    else:
        verdict = "Подозрительно"
    print(f"  {url}: {verdict} ({proba*100:.1f}%)")

# Сохраняем модель
joblib.dump(model, 'ml/model.pkl')
print("\nМодель сохранена в ml/model.pkl")
