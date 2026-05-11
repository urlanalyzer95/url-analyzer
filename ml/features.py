import re
import pandas as pd
from urllib.parse import urlparse

# Ровно те 14 признаков, что в вашем датасете
feature_cols = [
    'url_length', 'num_dots', 'num_hyphens', 'num_slashes', 'num_params',
    'has_ip', 'has_https', 'has_login', 'has_verify', 'has_account',
    'has_cp.php', 'has_admin', 'is_shortened', 'domain_length'
]

def extract_features(url: str) -> pd.DataFrame:
    url_str = str(url).lower().strip()
    parsed = urlparse(url_str)
    
    features = {
        'url_length': len(url_str),
        'num_dots': url_str.count('.'),
        'num_hyphens': url_str.count('-'),
        'num_slashes': url_str.count('/'),
        'num_params': len(re.findall(r'[?&]', url_str)),
        'has_ip': 1 if re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', url_str) else 0,
        'has_https': 1 if url_str.startswith('https') else 0,
        'has_login': 1 if 'login' in url_str else 0,
        'has_verify': 1 if 'verify' in url_str else 0,
        'has_account': 1 if 'account' in url_str else 0,
        'has_cp.php': 1 if 'cp.php' in url_str else 0,
        'has_admin': 1 if 'admin' in url_str else 0,
        'is_shortened': 1 if any(s in url_str for s in ['bit.ly', 'goo.gl', 'tinyurl']) else 0,
        'domain_length': len(parsed.netloc.split(':')[0])
    }
    return pd.DataFrame([features])[feature_cols]