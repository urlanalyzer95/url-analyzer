import re
import pandas as pd
import numpy as np

feature_cols = ['url_length','num_dots','num_hyphens','num_slashes','num_params',
                'has_ip','has_https','has_login','has_verify','has_account',
                'has_cp.php','has_admin','is_shortened','domain_length']

def extract_features(url):
    features = {}
    features['url_length'] = len(url)
    features['num_dots'] = url.count('.')
    features['num_hyphens'] = url.count('-')
    features['num_slashes'] = url.count('/')
    features['num_params'] = len(re.findall(r'[?&]', url))  
    features['has_ip'] = 1 if re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', url) else 0  # ✅ ФИКС!
    features['has_https'] = 1 if url.startswith('https://') else 0
    features['has_login'] = 1 if 'login' in url.lower() else 0
    features['has_verify'] = 1 if 'verify' in url.lower() else 0
    features['has_account'] = 1 if 'account' in url.lower() else 0
    features['has_cp.php'] = 1 if 'cp.php' in url.lower() else 0
    features['has_admin'] = 1 if 'admin' in url.lower() else 0
    features['is_shortened'] = 1 if any(x in url.lower() for x in ['bit.ly','tinyurl','t.co']) else 0
    
    try:  # ✅ Безопасный парсинг домена
        domain = re.search(r'https?://([^/]+)', url).group(1) if '://' in url else url.split('/')[0]
        features['domain_length'] = len(domain.replace('.',''))
    except:
        features['domain_length'] = len(url)
    
    return pd.DataFrame([features])[feature_cols]
