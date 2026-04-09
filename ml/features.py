import re
from urllib.parse import urlparse

def extract_features(url):
    url = str(url).lower().strip()
    
    features = []

    # БАЗОВЫЕ ПРИЗНАКИ
    features.append(len(url))  # url_length
    features.append(url.count('.'))  # num_dots
    features.append(url.count('-'))  # num_hyphens
    features.append(url.count('/'))  # num_slashes
    features.append(len(re.findall(r'[?&]', url)))  # num_params

    # ДОВЕРЕННЫЕ БРЕНДЫ
    trusted_brands = [
        'google', 'yandex', 'vk', 'wikipedia', 'github', 'youtube', 
        'facebook', 'instagram', 'twitter', 'amazon', 'apple', 
        'microsoft', 'stackoverflow', 'reddit', 'linkedin'
    ]
    features.append(1 if any(b in url for b in trusted_brands) else 0)

    # БЕЗОПАСНОСТЬ
    features.append(1 if re.search(r'\d{1,3}(\.\d{1,3}){3}', url) else 0)  # has_ip
    features.append(1 if url.startswith('https') else 0)  # has_https

    # ПОДОЗРИТЕЛЬНЫЕ СЛОВА
    suspicious_words = ['login', 'verify', 'account', 'cp.php', 'admin', 
                        'secure', 'update', 'confirm', 'signin', 'banking']
    for word in suspicious_words:
        features.append(1 if word in url else 0)

    # СОКРАЩАТЕЛИ ССЫЛОК
    shorteners = ['bit.ly', 'goo.gl', 'tinyurl', 'ow.ly', 'is.gd', 'buff.ly']
    features.append(1 if any(s in url for s in shorteners) else 0)

    # ОМОГЛИФЫ (подмена символов, например g00gle вместо google)
    has_omoglyph = 1 if re.search(r'0|1|3|4|5|7', url) and 'google' not in url else 0
    features.append(has_omoglyph)

    # ДОМЕН
    domain = urlparse(url).netloc
    features.append(len(domain))  # domain_length
    
    # ПОДОЗРИТЕЛЬНЫЕ TLD (.tk, .xyz, .top и т.д.)
    suspicious_tlds = ['.tk', '.xyz', '.top', '.ml', '.ga', '.cf']
    has_suspicious_tld = 1 if any(tld in domain for tld in suspicious_tlds) else 0
    features.append(has_suspicious_tld)

    return features
