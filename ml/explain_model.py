import joblib
import numpy as np
import pandas as pd
from ml.features import extract_features

class ModelExplainer:
    def __init__(self, model_path='ml/model.pkl', feature_cols_path='ml/feature_cols.pkl'):
        self.model = joblib.load(model_path)
        self.feature_names = joblib.load(feature_cols_path)
        self.global_importance = self.model.feature_importances_
        self.feature_comments = {
            'url_length': 'Длина URL (фишинговые часто длиннее)',
            'num_dots': 'Много точек (маскировка домена)',
            'num_hyphens': 'Много дефисов',
            'num_slashes': 'Много слешей',
            'num_params': 'Много параметров ? и &',
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
        try:
            self.means = joblib.load('ml/feature_means.pkl')
        except:
            self.means = None
            print("⚠️ feature_means.pkl не найден")

    def predict_with_explanation(self, url):
        features_raw = extract_features(url)
        features = features_raw.iloc[0].tolist()

        X = np.array(features).reshape(1, -1)
        proba = self.model.predict_proba(X)[0][1]
        pred = 1 if proba > 0.5 else 0

        reasons = self._generate_reasons(features, pred, proba)

        return {
            'prediction': 'phishing' if pred == 1 else 'legitimate',
            'probability': round(proba * 100, 2),
            'reasons': reasons,
            'global_importance': dict(zip(self.feature_names, self.global_importance.tolist()))
        }

    def _generate_reasons(self, features, pred, proba):
        reasons = []
        if pred == 1:
            for i, name in enumerate(self.feature_names):
                value = features[i]
                if name.startswith('has_') and value == 1:
                    reasons.append(f"⚠️ {self.feature_comments.get(name, name)}")
                elif self.means is not None and not name.startswith('has_'):
                    mean_val = self.means[i]
                    if value > mean_val * 1.5:
                        reasons.append(f"{self.feature_comments.get(name, name)} (значение {int(value)}, выше среднего)")
            if not reasons:
                reasons.append('URL содержит признаки, типичные для фишинга')
        else:
            reasons.append('✅ Подозрительных признаков не обнаружено')
        return reasons[:5]
