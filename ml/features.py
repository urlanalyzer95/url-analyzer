# ml/features.py
import re
import pandas as pd
from urllib.parse import urlparse

# Единый список признаков — порядок ВАЖЕН для совместимости с моделью
feature_cols = [
    'url_length', 'num_dots', 'num_hyphens', 'num_slashes', 'num_params',
    'has_ip', 'has_login', 'has_verify', 'has_account',
    'has_cp.php', 'has_admin', 'is_shortened', 'domain_length'
]

# Дефолтные значения на случай ошибки или невалидного URL
DEFAULT_FEATURES = {col: 0 for col in feature_cols}


def extract_features(url):
    try:
        url_str = str(url).lower().strip()
        
        # Защита от пустых/гигантских строк
        if not url_str or len(url_str) > 2048:
            return pd.DataFrame([DEFAULT_FEATURES])[feature_cols]

        parsed = urlparse(url_str)
        netloc = parsed.netloc.split(':')[0] if parsed.netloc else ''

        features = {
            'url_length': len(url_str),
            'num_dots': url_str.count('.'),
            'num_hyphens': url_str.count('-'),
            'num_slashes': url_str.count('/'),
            'num_params': len(re.findall(r'[?&]', url_str)),
            # \b гарантирует, что не сработает на "1.2.3.4" в пути
            'has_ip': 1 if re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', url_str) else 0,
            'has_login': 1 if 'login' in url_str else 0,
            'has_verify': 1 if 'verify' in url_str else 0,
            'has_account': 1 if 'account' in url_str else 0,
            'has_cp.php': 1 if 'cp.php' in url_str else 0,
            'has_admin': 1 if 'admin' in url_str else 0,
            'is_shortened': 1 if any(s in url_str for s in ['bit.ly', 'goo.gl', 'tinyurl']) else 0,
            'domain_length': len(netloc)
        }

        # Гарантируем порядок и заполнение пропусков
        safe_features = {col: features.get(col, 0) for col in feature_cols}
        return pd.DataFrame([safe_features])[feature_cols]

    except Exception:
        # Любой сбой → безопасный дефолт
        return pd.DataFrame([DEFAULT_FEATURES])[feature_cols]
