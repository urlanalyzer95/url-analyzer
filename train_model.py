import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier

df = pd.read_csv('data/processed/url_dataset_features.csv')

X = df.drop(columns=['url', 'label'])
y = df['label']

model = RandomForestClassifier(
    n_estimators=50,      # уменьшили с 100 до 50
    max_depth=10,         # ограничили глубину
    min_samples_split=5,  # минимальное количество образцов для разделения
    min_samples_leaf=2,   # минимальное количество образцов в листе
    random_state=42
)
model.fit(X, y)

joblib.dump(model, 'ml/model.pkl')

print("Модель обучена")
#запуск python train_model.py
