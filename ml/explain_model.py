# ml/explain_model.py
import joblib
import numpy as np
import pandas as pd
from ml.features import extract_features, feature_cols

class ModelExplainer:
    def __init__(self, model_path='ml/model.pkl'):
        self.model = joblib.load(model_path)
        self.feature_names = feature_cols.copy()
        
        # Важность признаков (для RandomForest)
        if hasattr(self.model, 'feature_importances_'):
            self.global_importance = self.model.feature_importances_
        else:
            # Для CalibratedClassifierCV берём важность базовой модели
            base = getattr(self.model, 'base_estimator', None)
            if base and hasattr(base, 'feature_importances_'):
                self.global_importance = base.feature_importances_
            else:
                self.global_importance = np.zeros(len(self.feature_names))
        
        self.feature_comments = {
            'url_length': 'Длина URL (фишинговые часто длиннее)',
            'num_dots': 'Много точек (маскировка домена)',
            'num_hyphens': 'Много дефисов',
            'num_slashes': 'Много слешей',
            'num_params': 'Много параметров ? и &',
            'has_ip': 'IP-адрес вместо домена (почти всегда фишинг)',
            'has_https': 'HTTPS-сертификат',
            'has_login': 'Слово "login" в URL',
            'has_verify': 'Слово "verify" в URL',
            'has_account': 'Слово "account" в URL',
            'has_cp.php': 'Слово "cp.php" в URL',
            'has_admin': 'Слово "admin" в URL',
            'is_shortened': 'Сервис сокращения ссылок (bit.ly, goo.gl)',
            'domain_length': 'Длина домена'
        }
        
        # Загрузка средних значений (опционально)
        try:
            self.means = joblib.load('ml/feature_means.pkl')
        except FileNotFoundError:
            self.means = None

    def predict_with_explanation(self, url):
        features_df = extract_features(url)
        features = features_df.iloc[0].tolist()
        X = np.array(features).reshape(1, -1)
        
        proba = self.model.predict_proba(X)[0][1]
        pred = 1 if proba > 0.5 else 0
        reasons = self._generate_reasons(features, pred, proba)
        
        return {
            'prediction': 'phishing' if pred == 1 else 'legitimate',
            'probability': round(proba * 100, 2),
            'reasons': reasons
        }

    def _generate_reasons(self, features, pred, proba):
        reasons = []
        if pred == 1:  # Фишинг
            for i, name in enumerate(self.feature_names):
                value = features[i]
                comment = self.feature_comments.get(name, name)
                
                if name.startswith('has_') and value == 1:
                    reasons.append(f"🔍 {comment}")
                elif self.means is not None and not name.startswith('has_'):
                    mean_val = self.means[i] if i < len(self.means) else 0
                    if mean_val > 0 and value > mean_val * 1.5:
                        reasons.append(f"📈 {comment} (значение {value})")
            
            if not reasons:
                reasons.append("URL содержит комбинацию признаков, типичных для фишинга")
        else:  # Легитимный
            reasons.append("✅ Подозрительных признаков не обнаружено")
        
        return reasons[:5]  # Максимум 5 причин
