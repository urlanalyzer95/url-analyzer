import pandas as pd
import joblib

# Загружаем модель
model = joblib.load('ml/model.pkl')
print("✅ Модель загружена")

# Загружаем признаки
df = pd.read_csv('data/processed/url_dataset_features.csv')
feature_columns = [col for col in df.columns if col not in ['url', 'label']]

# Находим нашу ссылку
url = 'http://educatingwellness.com/servicee/78c95/house-sites/update.php'
row = df[df['url'] == url]

if len(row) > 0:
    X = row[feature_columns]
    score = model.predict_proba(X)[0][1]
    print(f"\nURL: {url}")
    print(f"ML score: {score:.2f}")
    print(f"Вердикт модели: {'ОПАСНО' if score > 0.5 else 'БЕЗОПАСНО'}")
else:
    print(f"\n❌ URL не найден в features.csv")