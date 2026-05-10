import re
import math
import pandas as pd
from urllib.parse import urlparse

SUSPICIOUS_TLDS = {
    'tk', 'ml', 'ga', 'cf', 'gq',
    'xyz', 'top', 'club', 'work', 'click',
    'link', 'win', 'loan', 'men', 'stream'
}

SHORTENERS = {'bit.ly', 'goo.gl', 'tinyurl', 't.co', 'ow.ly', 'is.gd',
              'buff.ly', 'shorte.st', 'bc.vc', 'adf.ly'}

feature_cols = [
    'has_ip',
    'has_https_in_domain',
    'has_at',
    'has_double_slash',
    'has_login',
    'has_verify',
    'has_account',
    'has_cp.php',
    'has_admin',
    'is_shortened',
    'has_suspicious_tld',
    'has_params',
    'digit_ratio_domain',
    'entropy_domain'
]

def _entropy(s):
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob)

def extract_features(url):
    url_str = str(url).lower().strip()
    parsed = urlparse(url_str)
    netloc = parsed.netloc
    path = parsed.path

    features = {}

    features['has_ip'] = 1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url_str) else 0
    features['has_https_in_domain'] = 1 if 'https' in netloc else 0
    features['has_at'] = 1 if '@' in url_str else 0
    features['has_double_slash'] = 1 if '//' in path else 0

    features['has_login'] = 1 if 'login' in url_str else 0
    features['has_verify'] = 1 if 'verify' in url_str else 0
    features['has_account'] = 1 if 'account' in url_str else 0
    features['has_cp.php'] = 1 if 'cp.php' in url_str else 0
    features['has_admin'] = 1 if 'admin' in url_str else 0

    features['is_shortened'] = 1 if any(s in url_str for s in SHORTENERS) else 0

    if netloc:
        tld = netloc.split('.')[-1] if '.' in netloc else ''
        features['has_suspicious_tld'] = 1 if tld in SUSPICIOUS_TLDS else 0
    else:
        features['has_suspicious_tld'] = 0

    features['has_params'] = 1 if re.search(r'[?&]', url_str) else 0

    if netloc:
        digits = sum(c.isdigit() for c in netloc)
        features['digit_ratio_domain'] = digits / len(netloc)
        features['entropy_domain'] = _entropy(netloc)
    else:
        features['digit_ratio_domain'] = 0.0
        features['entropy_domain'] = 0.0

    return pd.DataFrame([features])[feature_cols]