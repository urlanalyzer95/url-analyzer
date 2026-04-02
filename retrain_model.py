import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import os

print("🔄 ЗАГРУЗКА НОВОГО ДАТАСЕТА...")
df = pd.read_csv('data/processed/url_dataset_features_v2.csv')

feature_cols = [c for c in df.columns if c not in ['url', 'label']]
X = df[feature_cols]
y = df['label']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

print(f"✅ Записей: {len(df)}")
print(f"✅ Признаков: {len(feature_cols)}")
print(f"✅ Обучающая: {len(X_train)}")
print(f"✅ Тестовая: {len(X_test)}")
print(f"   Класс 0 (безопасные): {(y == 0).sum()}")
print(f"   Класс 1 (опасные): {(y == 1).sum()}")

# Random Forest
print("\n🌲 ОБУЧЕНИЕ RANDOM FOREST...")
rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
rf.fit(X_train, y_train)
rf_pred = rf.predict(X_test)
rf_acc = accuracy_score(y_test, rf_pred)
print(f"   Точность: {rf_acc:.4f}")

# XGBoost
print("\n🚀 ОБУЧЕНИЕ XGBOOST...")
xgb = XGBClassifier(n_estimators=100, random_state=42, use_label_encoder=False, eval_metric='logloss')
xgb.fit(X_train, y_train)
xgb_pred = xgb.predict(X_test)
xgb_acc = accuracy_score(y_test, xgb_pred)
print(f"   Точность: {xgb_acc:.4f}")

# Сохранение
os.makedirs('ml', exist_ok=True)
joblib.dump(rf, 'ml/model_rf_v2.pkl')
joblib.dump(xgb, 'ml/model_xgb.pkl')

print("\n✅ МОДЕЛИ СОХРАНЕНЫ:")
print("   - ml/model_rf_v2.pkl")
print("   - ml/model_xgb.pkl")

if rf_acc > xgb_acc:
    print(f"\n🏆 Лучшая модель: RandomForest ({rf_acc:.4f})")
else:
    print(f"\n🏆 Лучшая модель: XGBoost ({xgb_acc:.4f})")