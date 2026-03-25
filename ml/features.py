import re
from urllib.parse import urlparse

def extract_features(url):
    url = str(url).lower().strip()#
    
    features = []

    # БАЗА
    features.append(len(url))  # url_length
    features.append(url.count('.'))  # num_dots
    features.append(url.count('-'))  # num_hyphens
    features.append(url.count('/'))  # num_slashes
    features.append(len(re.findall(r'[?&]', url)))  # num_params

    # БЕЗОПАСНОСТЬ
    features.append(1 if re.search(r'\d{1,3}(\.\d{1,3}){3}', url) else 0)  # has_ip
    features.append(1 if url.startswith('https') else 0)  # has_https

    # СЛОВА
    for word in ['login', 'verify', 'account', 'cp.php', 'admin']:
        features.append(1 if word in url else 0)

    # Сокращатели
    features.append(1 if any(s in url for s in ['bit.ly', 'goo.gl', 'tinyurl']) else 0)

    # Домен
    domain = urlparse(url).netloc
    features.append(len(domain))  # domain_length

    return features
