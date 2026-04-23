# ml/explain_model.py
import joblib
import numpy as np
from ml.features import extract_features

class ModelExplainer:
    def __init__(self, model_path='ml/model.pkl', feature_cols_path='ml/feature_cols.pkl'):
        self.model = joblib.load(model_path)
        self.feature_names = joblib.load(feature_cols_path)
        self.global_importance = self.model.feature_importances_

        # Человеко-читаемые описания признаков (порядок должен совпадать с feature_names)
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
        # Загружаем средние значения для признаков (если есть)
        try:
            self.means = joblib.load('ml/feature_means.pkl')
        except:
            self.means = None

    def predict_with_explanation(self, url):
        """
        Возвращает dict с prediction, probability и списком причин.
        """
        features = extract_features(url)  # список из 14 чисел
        # Преобразуем в numpy массив (1, 14)
        X = np.array(features).reshape(1, -1)
        proba = self.model.predict_proba(X)[0][1]  # вероятность фишинга
        pred = int(proba > 0.5)

        reasons = self._generate_reasons(features, pred, proba)

        return {
            'prediction': 'phishing' if pred == 1 else 'legitimate',
            'probability': round(proba * 100, 2),
            'reasons': reasons
        }

    def _generate_reasons(self, features, pred, proba):
        """
        Генерирует список причин, почему URL опасен или безопасен.
        features - список чисел (длина 14)
        """
        reasons = []
        if pred == 1:
            # Ищем признаки, которые повышают вероятность
            # Для бинарных признаков: если признак == 1, добавляем комментарий
            # Для числовых: сравниваем с глобальным средним (если есть)
            for i, name in enumerate(self.feature_names):
                value = features[i]
                if name.startswith('has_') and value == 1:
                    reasons.append(self.feature_comments.get(name, name))
                elif self.means is not None and not name.startswith('has_'):
                    # числовой признак, проверяем отклонение
                    mean_val = self.means[i]
                    if value > mean_val * 1.5:
                        reasons.append(f'{self.feature_comments.get(name, name)} (значение {value}, выше среднего)')
            if not reasons:
                reasons.append('URL содержит признаки, типичные для фишинга')
        else:
            # Для безопасных URL: можно указать, что подозрительных признаков нет
            reasons.append('Подозрительных признаков не обнаружено')
        return reasons[:5]  # не более 5 причин
