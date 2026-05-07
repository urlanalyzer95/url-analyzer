import re
import pandas as pd
from urllib.parse import urlparse

feature_cols = [
    'has_ip', 'has_login', 'has_verify', 'has_account',
    'has_cp.php', 'has_admin', 'is_shortened'
]

DEFAULT_FEATURES = {col: 0 for col in feature_cols}

def extract_features(url):
    try:
        url_str = str(url).lower().strip()
        if not url_str or len(url_str) > 2048:
            return pd.DataFrame([DEFAULT_FEATURES])[feature_cols]
        
        features = {
            'has_ip': 1 if re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', url_str) else 0,
            'has_login': 1 if 'login' in url_str else 0,
            'has_verify': 1 if 'verify' in url_str else 0,
            'has_account': 1 if 'account' in url_str else 0,
            'has_cp.php': 1 if 'cp.php' in url_str else 0,
            'has_admin': 1 if 'admin' in url_str else 0,
            'is_shortened': 1 if any(s in url_str for s in ['bit.ly', 'goo.gl', 'tinyurl']) else 0,
        }
        safe = {col: features.get(col, 0) for col in feature_cols}
        return pd.DataFrame([safe])[feature_cols]
    except Exception:
        return pd.DataFrame([DEFAULT_FEATURES])[feature_cols]
