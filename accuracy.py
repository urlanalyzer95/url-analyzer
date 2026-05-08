import pandas as pd
import joblib
from pathlib import Path
import sklearn
from sklearn.metrics import (
    accuracy_score, 
    precision_score, 
    recall_score, 
    f1_score,
    roc_auc_score,
    classification_report,
    confusion_matrix
)

# Проверка версии
print(f"🔥 Версия scikit-learn: {sklearn.__version__}")

# 1. Загрузка модели
print("🔄 Загрузка модели...")
try:
    model = joblib.load('ml/model.pkl')
    print("✅ Модель загружена из ml/model.pkl")
except FileNotFoundError:
    print("❌ Ошибка: Файл ml/model.pkl не найден! Сначала обучи модель.")
    exit()

def evaluate_dataset(filepath, name):
    """Оценивает модель на датасете и возвращает метрики"""
    print(f"\n{'='*50}")
    print(f"📂 ПРОВЕРКА: {name}")
    print(f"📄 Файл: {filepath}")
    print(f"{'='*50}")

    if not Path(filepath).exists():
        print(f"❌ Файл не найден: {filepath}")
        return None

    # Загружаем CSV
    df = pd.read_csv(filepath)
    print(f"📊 Записей в датасете: {len(df)}")

    # Разделяем на признаки (X) и метки (y)
    y_true = df['label']
    X = df.drop(columns=['label', 'url'], errors='ignore') 

    # Проверяем, совпадают ли колонки с моделью
    if len(X.columns) != model.n_features_in_:
        print(f"⚠️ Внимание: Ожидается {model.n_features_in_} признаков, а в файле {len(X.columns)}.")
        return None

    # Предсказание
    print("🔮 Делаем предсказания...")
    y_pred = model.predict(X)
    y_proba = model.predict_proba(X)[:, 1]  # Вероятности для ROC-AUC

    # Все метрики
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    try:
        auc = roc_auc_score(y_true, y_proba)
    except:
        auc = 0.0

    print(f"\n📊 МЕТРИКИ:")
    print(f"   Accuracy:  {acc*100:.2f}%")
    print(f"   Precision: {prec*100:.2f}%")
    print(f"   Recall:    {rec*100:.2f}% ⭐")
    print(f"   F1-Score:  {f1*100:.2f}%")
    print(f"   ROC-AUC:   {auc*100:.2f}%")

    # Подробный отчёт
    print(f"\n📋 Classification Report:")
    print(classification_report(y_true, y_pred, target_names=['Safe', 'Phishing'], zero_division=0))

    # Матрица ошибок
    cm = confusion_matrix(y_true, y_pred)
    print(f"\n🔲 Confusion Matrix:")
    print(f"   {cm}")
    print(f"\n   Расшифровка:")
    print(f"   • TN (верно безопасные): {cm[0][0]}")
    print(f"   • FP (ложная тревога):   {cm[0][1]}")
    print(f"   • FN (пропущен фишинг):  {cm[1][0]} ⚠️")
    print(f"   • TP (верно фишинг):     {cm[1][1]}")

    # Возвращаем метрики для сравнения
    return {
        'accuracy': acc,
        'precision': prec,
        'recall': rec,
        'f1': f1,
        'auc': auc
    }

# --- ЗАПУСК ---

print("\n" + "="*60)
print("🚀 СРАВНЕНИЕ ДАТАСЕТОВ")
print("="*60)

# Пути к твоим файлам
dataset_1 = 'data/processed/url_dataset_features.csv'
dataset_2 = 'data/processed/url_dataset2_features4.csv'

# Оцениваем оба датасета
metrics_1 = evaluate_dataset(dataset_1, "Основной датасет (url_dataset_features.csv)")
metrics_2 = evaluate_dataset(dataset_2, "Новый датасет (url_dataset2_features4.csv)")

# Итоговое сравнение
if metrics_1 and metrics_2:
    print(f"\n{'='*50}")
    print("🏆 ИТОГОВОЕ СРАВНЕНИЕ")
    print(f"{'='*50}")
    print(f"{'Метрика':<15} {'Dataset 1':>12} {'Dataset 2':>12}")
    print(f"{'-'*50}")
    print(f"{'Accuracy':<15} {metrics_1['accuracy']*100:>11.2f}% {metrics_2['accuracy']*100:>11.2f}%")
    print(f"{'Precision':<15} {metrics_1['precision']*100:>11.2f}% {metrics_2['precision']*100:>11.2f}%")
    print(f"{'Recall ⭐':<15} {metrics_1['recall']*100:>11.2f}% {metrics_2['recall']*100:>11.2f}%")
    print(f"{'F1-Score':<15} {metrics_1['f1']*100:>11.2f}% {metrics_2['f1']*100:>11.2f}%")
    print(f"{'ROC-AUC':<15} {metrics_1['auc']*100:>11.2f}% {metrics_2['auc']*100:>11.2f}%")
    
    print(f"\n🎯 РЕКОМЕНДАЦИЯ:")
    # Recall важнее всего для детекции фишинга!
    if metrics_1['recall'] > metrics_2['recall']:
        print(f"   ✅ Dataset 1 лучше по Recall ({metrics_1['recall']*100:.2f}% vs {metrics_2['recall']*100:.2f}%)")
        print(f"   → Меньше пропускает реальный фишинг")
    elif metrics_2['recall'] > metrics_1['recall']:
        print(f"   ✅ Dataset 2 лучше по Recall ({metrics_2['recall']*100:.2f}% vs {metrics_1['recall']*100:.2f}%)")
        print(f"   → Меньше пропускает реальный фишинг")
    else:
        print(f"   🤝 Recall одинаковый, смотрим на F1...")
        if metrics_1['f1'] >= metrics_2['f1']:
            print(f"   ✅ Dataset 1 (F1: {metrics_1['f1']*100:.2f}%)")
        else:
            print(f"   ✅ Dataset 2 (F1: {metrics_2['f1']*100:.2f}%)")
else:
    print("\n❌ Не удалось сравнить датасеты (ошибка в одном из файлов)")