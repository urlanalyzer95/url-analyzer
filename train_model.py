import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier

df = pd.read_csv('data/processed/url_dataset_features.csv')

X = df.drop(columns=['url', 'label'])
y = df['label']

model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X, y)

joblib.dump(model, 'ml/model.pkl')

print("Модель обучена")
