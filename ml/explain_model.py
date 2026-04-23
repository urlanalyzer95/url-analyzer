import joblib
import numpy as np
import pandas as pd
from ml.features import extract_features

class ModelExplainer:
    def __init__(self, model_path='ml/model.pkl', feature_cols_path='ml/feature_cols.pkl'):
        self.model = joblib.load(model_path)
        self.feature_names = joblib.load(feature_cols_path)
        self.global_importance = self.model.feature_importances_

        # Человеко-читаемые описания признаков
        self.feature_comments = {
            'url_length': 'Длина URL (фишинговые часто длиннее)',
            'num_dots': 'Количество точек (маскировка домена)',
            'num_hyphens': 'Количество дефисов',
            'num_slashes': 'Количество слешей',
            'num_params': 'Количество параметров ? и &',
            'has_ip': 'IP-адрес вместо домена (почти всегда фишинг)',
            'has_https': 'HTTPS-сертификат (фишеры используют бесплатные SSL)',
            'has_login': 'Слово "login" в URL',
            'has_verify': 'Слово "verify" в URL',
            'has_account': 'Слово "account" в URL',
            'has_cp.php': 'Слово "cp.php" в URL',
            'has_admin': 'Слово "admin" в URL',
            'is_shortened': 'Сервис сокращения ссылок (bit.ly, goo.gl)',
            'domain_length': 'Длина домена (длинные поддомены подозрительны)'
        }

        # Средние значения признаков (загружаем или вычисляем)
        try:
            self.feature_means = joblib.load('ml/feature_means.pkl')
        except:
            self.feature_means = None

    def predict_with_explanation(self, url):
        """
        Возвращает предсказание + список причин в человеческом виде
        """
        features = extract_features(url)
        features_array = np.array(features).reshape(1, -1)
        proba = self.model.predict_proba(features_array)[0][1]
        pred = 1 if proba > 0.5 else 0

        # Генерируем объяснения
        reasons = self._generate_reasons(features, pred, proba)

        return {
            'prediction': 'phishing' if pred == 1 else 'legitimate',
            'probability': round(proba * 100, 1),
            'global_importance': dict(zip(self.feature_names, self.global_importance)),
            'reasons': reasons[:5]  # Топ-5 причин
        }

    def _generate_reasons(self, features, pred, proba):
        """Генерация человеко-читаемых причин"""
        reasons = []

        # Топ-3 глобально важных признака
        top_features = np.argsort(self.global_importance)[-3:][::-1]
        for idx in top_features:
            name = self.feature_names[idx]
            value = features[idx]
            comment = self.feature_comments.get(name, name)
            
            if pred == 1 and value > 0:  # Фишинг + активный признак
                reasons.append(f"⚠️ {comment}: значение {value}")
            elif pred == 0 and value == 0:
                reasons.append(f"✅ {comment}: значение {value}")

        # Специфичные для фишинга признаки
        if pred == 1:
            suspicious_features = [
                'has_ip', 'has_login', 'has_verify', 'has_account', 
                'has_admin', 'has_cp.php', 'is_shortened'
            ]
            for name in suspicious_features:
                if name in self.feature_names:
                    idx = self.feature_names.index(name)
                    if features[idx] == 1:
                        reasons.append(f"🚨 {self.feature_comments[name]}")

        # Если мало причин — добавляем общие
        if len(reasons) < 2:
            if pred == 1:
                reasons.append("Общая структура URL типична для фишинга")
            else:
                reasons.append("Подозрительных признаков не обнаружено")

        return reasons

    def save_means(self, csv_path='data/processed/url_dataset_features.csv'):
        """Вычислить и сохранить средние значения признаков"""
        df = pd.read_csv(csv_path)
        self.feature_means = df[self.feature_names].mean().values
        joblib.dump(self.feature_means, 'ml/feature_means.pkl')
        print("✅ Средние значения сохранены: ml/feature_means.pkl")

# Тест
if __name__ == "__main__":
    explainer = ModelExplainer()
    
    # Тест URL
    test_urls = [
        "http://login.secure-bank.com.verify-account.ru/login?session=abc123",
        "https://google.com",
        "http://185.13.55.2/admin/cp.php"
    ]
    
    for url in test_urls:
        result = explainer.predict_with_explanation(url)
        print(f"\n🔍 {url}")
        print(f"Вердикт: {result['prediction']} ({result['probability']}%)")
        print("Причины:")
        for reason in result['reasons']:
            print(f"  {reason}")
