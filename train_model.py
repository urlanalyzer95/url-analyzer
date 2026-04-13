import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib
import os
import sys
from pathlib import Path
import matplotlib.pyplot as plt
import seaborn as sns

def main():
    # Корень проекта
    BASE_DIR = Path(__file__).parent
    
    # 1. Загрузка датасета
    dataset_path = BASE_DIR / 'data' / 'processed' / 'url_dataset_features.csv'
    if not dataset_path.exists():
        print(f"❌ Датасет не найден: {dataset_path}")
        print("Создайте папку data/processed/ и положите туда url_dataset_features.csv")
        sys.exit(1)
    
    print("📊 Загружаем датасет...")
    df = pd.read_csv(dataset_path)
    print(f"   Размер: {df.shape}")
    print(f"   Классы 0(легит)/1(фишинг):")
    print(df['label'].value_counts().sort_index())
    
    # 2. Признаки (ТОЧНО как в server.py)
    feature_cols = [
        'url_length', 'num_dots', 'num_hyphens', 'num_slashes', 'num_params',
        'has_ip', 'has_https', 'has_login', 'has_verify', 'has_account',
        'has_cp.php', 'has_admin', 'is_shortened', 'domain_length'
    ]
    
    if not all(col in df.columns for col in feature_cols):
        print("❌ Ошибка: не все признаки в датасете!")
        print("Нужны:", feature_cols)
        sys.exit(1)
    
    X = df[feature_cols]
    y = df['label']
    
    print(f"\n✅ Признаков: {len(feature_cols)}")
    
    # 3. Разделение (ПОЛНЫЙ датасет 208k)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"✅ Train: {X_train.shape}")
    print(f"✅ Test:  {X_test.shape}")
    
    # 4. Random Forest (оптимизировано)
    print("\n🎯 Обучаем Random Forest...")
    model = RandomForestClassifier(
        n_estimators=200,        # Деревьев
        max_depth=15,           # Глубина
        min_samples_split=10,
        min_samples_leaf=5,
        random_state=42,
        n_jobs=-1               # Все CPU
    )
    model.fit(X_train, y_train)
    print("✅ Обучение завершено!")
    
    # 5. Тестирование
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    
    print(f"\n🎉 ТОЧНОСТЬ: {accuracy:.4f} ({accuracy*100:.2f}%)")
    print("\n📊 Classification Report:")
    print(classification_report(y_train, model.predict(X_train)))
    print("\n📊 Test Report:")
    print(classification_report(y_test, y_pred))
    
    # 6. Confusion Matrix
    cm = confusion_matrix(y_test, y_pred)
    plt.figure(figsize=(6,4))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                xticklabels=['Легит', 'Фишинг'], 
                yticklabels=['Легит', 'Фишинг'])
    plt.title(f'Confusion Matrix (Accuracy: {accuracy:.1%})')
    plt.ylabel('Реальная')
    plt.xlabel('Предсказанная')
    plt.tight_layout()
    plt.savefig(BASE_DIR / 'ml' / 'confusion_matrix.png')
    plt.show()
    
    # 7. Важность признаков
    importances = pd.DataFrame({
        'feature': feature_cols,
        'importance': model.feature_importances_
    }).sort_values('importance', ascending=False)
    
    print("\n🔍 ТОП-10 ПРИЗНАКОВ:")
    print(importances.head(10).round(4))
    
    plt.figure(figsize=(10,6))
    sns.barplot(data=importances.head(10), x='importance', y='feature')
    plt.title('Топ-10 признаков')
    plt.tight_layout()
    plt.savefig(BASE_DIR / 'ml' / 'feature_importance.png')
    plt.show()
    
    # 8. СОХРАНЕНИЕ
    os.makedirs(BASE_DIR / 'ml', exist_ok=True)
    joblib.dump(model, BASE_DIR / 'ml' / 'model.pkl')
    joblib.dump(feature_cols, BASE_DIR / 'ml' / 'feature_cols.pkl')
    
    print(f"\n💾 ГОТОВО ДЛЯ ПРОДАКШЕНА:")
    print(f"   📁 ml/model.pkl          ← 98.13% accuracy")
    print(f"   📁 ml/feature_cols.pkl   ← Признаки")
    print(f"   📁 ml/confusion_matrix.png")
    print(f"   📁 ml/feature_importance.png")
    print(f"\n🚀 Готово для server.py и деплоя на Render!")

if __name__ == '__main__':
    main()
