import re
import pandas as pd
from urllib.parse import urlparse

feature_cols = [
    'url_length', 'num_dots', 'num_hyphens', 'num_slashes', 'num_params',
    'has_ip', 'has_https', 'has_login', 'has_verify', 'has_account',
    'has_cp.php', 'has_admin', 'is_shortened', 'domain_length'
]

def extract_features(url):
    url_str = str(url).lower().strip()
    features = {}

    # Базовые
    features['url_length'] = len(url_str)
    features['num_dots'] = url_str.count('.')
    features['num_hyphens'] = url_str.count('-')
    features['num_slashes'] = url_str.count('/')
    features['num_params'] = len(re.findall(r'[?&]', url_str))

    # Безопасность
    features['has_ip'] = 1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url_str) else 0
    features['has_https'] = 1 if url_str.startswith('https') else 0

    # Подозрительные слова
    features['has_login'] = 1 if 'login' in url_str else 0
    features['has_verify'] = 1 if 'verify' in url_str else 0
    features['has_account'] = 1 if 'account' in url_str else 0
    features['has_cp.php'] = 1 if 'cp.php' in url_str else 0
    features['has_admin'] = 1 if 'admin' in url_str else 0

    # Сокращатели
    shorteners = ['bit.ly', 'goo.gl', 'tinyurl']
    features['is_shortened'] = 1 if any(s in url_str for s in shorteners) else 0

    # Домен
    parsed = urlparse(url_str)
    features['domain_length'] = len(parsed.netloc)

    return pd.DataFrame([features])[feature_cols]
