import sys
import json
import sqlite3
import os
import re
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify
import pandas as pd
import joblib
import redis

print("=== SERVER STARTING ===", file=sys.stderr)
sys.stderr.flush()

app = Flask(__name__)

# Redis подключение (с fallback)
try:
    redis_client = redis.from_url(os.environ.get('REDIS_URL', 'redis://localhost:6379/0'))
    print("✅ Redis подключен", file=sys.stderr)
except:
    print("⚠️ Redis недоступен, использую память", file=sys.stderr)
    redis_client = None

# ========== НОРМАЛИЗАЦИЯ И ВАЛИДАЦИЯ ==========
def normalize_url(url):
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    url = url.lower()
    url = url.rstrip('/')
    return url

def is_valid_url(url):
    if not url or not url.startswith(('http://', 'https://')) or ' ' in url:
        return False
    try:
        domain_part = url.split('/')[2].split(':')[0]
        if '.' not in domain_part:
            return False
        ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        if ip_pattern.match(domain_part):
            return True
        invalid_chars = [',', ';', '|', '\\', '^', '`', '[', ']', '{', '}', '<', '>', '"', "'"]
        if any(char in domain_part for char in invalid_chars):
            return False
        domain_pattern = re.compile(r'^[a-z0-9.-]+$')
        return bool(domain_pattern.match(domain_part))
    except:
        return False

# ========== ЭВРИСТИКИ ==========
def has_homoglyphs(url):
    dangerous_chars = ['а', 'е', 'о', 'р', 'с', 'у', 'х']
    return any(char in url.lower() for char in dangerous_chars)

def has_encoding(url):
    return bool(re.search(r'%[0-9A-Fa-f]{2}', url))

def has_suspicious_path(url):
    suspicious_paths = ['login', 'verify', 'secure', 'account', 'banking', 'payment', 'update', 'confirm']
    try:
        path_parts = url.split('/')[3:]
        return any(word in part.lower() for part in path_parts for word in suspicious_paths)
    except:
        return False

def has_suspicious_params(url):
    suspicious_params = ['redirect', 'url', 'return', 'next', 'goto', 'target', 'redir']
    if '?' in url:
        params = url.split('?')[1].lower()
        return any(param + '=' in params for param in suspicious_params)
    return False

def is_short_domain(url):
    try:
        domain = url.split('/')[2].split(':')[0]
        main_part = domain.split('.')[0]
        legitimate_short = ['ya', 'vk', 'ok', 'fb', 'gg', 'go', 'im', 'tv', 'io', 'ru', 'com']
        return main_part not in legitimate_short and len(main_part) <= 3
    except:
        return False

def has_numbers_in_domain(url):
    try:
        domain = url.split('/')[2].split(':')[0]
        return sum(c.isdigit() for c in domain) > 5
    except:
        return False

def has_many_subdomains(url):
    try:
        domain = url.split('/')[2].split(':')[0]
        subdomains = domain.split('.')[:-2]
        return len(subdomains) > 3
    except:
        return False

def is_localhost(url):
    local_patterns = [r'localhost', r'127\.0\.0\.1', r'192\.168\.\d{1,3}\.\d{1,3}', r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}']
    return any(re.search(pattern, url) for pattern in local_patterns)

def is_typosquatting(url):
    popular_domains = ['google', 'facebook', 'youtube', 'vk', 'mail', 'yandex', 'gmail', 'yahoo', 'instagram', 'twitter', 'whatsapp', 'telegram', 'github']
    try:
        domain = url.split('/')[2].lower().split(':')[0]
        for popular in popular_domains:
            if popular in domain and popular != domain and len(domain) > len(popular) + 1:
                return True
    except:
        pass
    return False

def is_suspicious_tld(url):
    suspicious_tlds = ['.xyz', '.top', '.club', '.online', '.site', '.pw', '.cc', '.tk', '.ml', '.ga', '.cf', '.bid', '.win']
    return any(tld in url for tld in suspicious_tlds)

def has_redirects(url):
    redirects = ['redirect=', 'url=', 'return=', 'next=', 'goto=']
    return any(redirect in url for redirect in redirects)

def is_too_long(url):
    return len(url) > 200

def has_brand_phishing(url):
    brands = ['paypal', 'wellsfargo', 'google', 'apple', 'microsoft', 'amazon', 'facebook', 'instagram', 'bank', 'sberbank', 'vtb', 'tinkoff', 'alfabank']
    try:
        url_lower = url.lower()
        for brand in brands:
            if brand in url_lower:
                legitimate = ['paypal.com', 'google.com', 'apple.com', 'microsoft.com', 'amazon.com']
                if not any(legit in url_lower for legit in legitimate):
                    return True
    except:
        pass
    return False

def is_ip_with_port(url):
    try:
        ip_pattern = re.compile(r'https?://(\d{1,3}\.){3}\d{1,3}:\d+')
        return bool(ip_pattern.search(url))
    except:
        return False

def has_suspicious_domain_pattern(url):
    try:
        domain = url.split('/')[2].lower().split(':')[0]
        return domain.count('-') > 3 or domain.count('.') > 4 or re.search(r'[bcdfghjklmnpqrstvwxyz]{6,}', domain)
    except:
        return False

# ========== ЗАГРУЗКА МОДЕЛИ (Render-совместимая) ==========
print("Loading features and model...", file=sys.stderr)
sys.stderr.flush()

model = None
features_df = None
feature_columns = []

# Сначала пробуем модель
try:
    if os.path.exists('ml/model.pkl'):
        model = joblib.load('ml/model.pkl')
        print("✅ Модель загружена", file=sys.stderr)
    else:
        print("⚠️ ml/model.pkl не найден", file=sys.stderr)
except Exception as e:
    print(f"⚠️ Ошибка загрузки модели: {e}", file=sys.stderr)
    model = None

# Потом датасет (опционально)
try:
    if os.path.exists('data/processed/url_dataset_features.csv'):
        features_df = pd.read_csv('data/processed/url_dataset_features.csv')
        feature_columns = [col for col in features_df.columns if col not in ['url', 'label']]
        print(f"✅ Датасет: {len(features_df)} записей, {len(feature_columns)} фич", file=sys.stderr)
    else:
        print("ℹ️ Датасет не найден, использую только эвристики", file=sys.stderr)
except Exception as e:
    print(f"⚠️ Ошибка загрузки датасета: {e}", file=sys.stderr)

print("🚀 Сервер готов к работе!", file=sys.stderr)
sys.stderr.flush()

# ========== REDIS КЭШ (с fallback) ==========
def get_cached(url):
    if redis_client:
        try:
            cached = redis_client.get(f"url:{url}")
            if cached:
                redis_client.incr('stats:hits')
                return json.loads(cached)
        except:
            pass
    redis_client.incr('stats:misses') if redis_client else None
    return None

def set_cached(url, data):
    if redis_client:
        try:
            redis_client.setex(f"url:{url}", 3600, json.dumps(data))
        except:
            pass

# ========== РОУТЫ ==========
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/health')
def health():
    return jsonify({
        'status': 'ok',
        'model_loaded': model is not None,
        'dataset_loaded': features_df is not None,
        'redis_available': redis_client is not None
    })

@app.route('/stats')
def stats():
    if redis_client:
        try:
            hits = int(redis_client.get('stats:hits') or 0)
            misses = int(redis_client.get('stats:misses') or 0)
            return jsonify({
                'cache_hits': hits,
                'cache_misses': misses,
                'hit_rate': round(hits/(hits+misses)*100, 1) if hits+misses > 0 else 0,
                'model_available': model is not None
            })
        except:
            pass
    return jsonify({'error': 'Stats unavailable'})

@app.route('/check', methods=['POST'])
def check_url():
    data = request.json
    raw_url = data.get('url', '').strip()
    
    if not raw_url:
        return jsonify({'error': 'URL не указан'}), 400
    
    url = normalize_url(raw_url)
    
    if not is_valid_url(url):
        return jsonify({
            'url': raw_url,
            'verdict': 'invalid',
            'verdict_text': 'НЕВАЛИДНЫЙ URL',
            'score': 0,
            'explanations': [
                'URL должен начинаться с http:// или https://',
                'URL не должен содержать пробелов или спецсимволов',
                'Пример: https://google.com'
            ]
        }), 400
    
    if is_localhost(url):
        return jsonify({
            'url': url,
            'verdict': 'warning',
            'verdict_text': 'ЛОКАЛЬНЫЙ АДРЕС',
            'score': 0,
            'explanations': ['Локальные адреса (localhost, 192.168.x.x) не проверяются']
        })
    
    # Проверяем кэш
    cached = get_cached(url)
    if cached:
        return jsonify(cached)
    
    # ML предсказание (если возможно)
    base_score = 0.3  # Базовый для новых URL
    
    if model and features_df is not None:
        try:
            url_row = features_df[features_df['url'] == url]
            if not url_row.empty:
                X = url_row[feature_columns]
                score = model.predict_proba(X)[0][1]
                base_score = float(score)
                print(f"ML score={base_score:.2f} для {url}", file=sys.stderr)
        except Exception as e:
            print(f"ML ошибка: {e}", file=sys.stderr)
    
    score = base_score
    
    # Корректировка эвристиками
    if score < 0.4:
        if has_numbers_in_domain(url):
            score = 0.45
        elif is_short_domain(url):
            score = 0.45
        elif has_many_subdomains(url):
            score = 0.45
        elif is_suspicious_tld(url):
            score = 0.45
    
    if has_brand_phishing(url) and score < 0.7:
        score = 0.75
    
    if is_ip_with_port(url):
        score = 0.8
    
    if has_suspicious_domain_pattern(url) and score < 0.5:
        score = 0.55
    
    # Вердикт
    if score > 0.7:
        verdict = "dangerous"
        verdict_text = "ОПАСНО"
    elif score > 0.4:
        verdict = "suspicious"
        verdict_text = "ПОДОЗРИТЕЛЬНО"
    else:
        verdict = "safe"
        verdict_text = "БЕЗОПАСНО"
    
    # Объяснения
    explanations = []
    if not url.startswith('https'):
        explanations.append("Отсутствует защищенное соединение HTTPS")
    if 'login' in url or 'verify' in url or 'secure' in url:
        explanations.append("Обнаружены подозрительные слова")
    if 'bit.ly' in url or 'goo.gl' in url:
        explanations.append("Сервис сокращения ссылок")
    if re.search(r'https?://(\d{1,3}\.){3}\d{1,3}', url):
        explanations.append("IP-адрес вместо домена")
    if '@' in url:
        explanations.append("Символ @ (может маскировать домен)")
    if has_homoglyphs(url):
        explanations.append("Кириллические символы (омоглифы)")
    if has_encoding(url):
        explanations.append("Закодированные символы (%XX)")
    if has_suspicious_path(url):
        explanations.append("Подозрительный путь")
    if has_suspicious_params(url):
        explanations.append("Параметры перенаправления")
    if is_short_domain(url):
        explanations.append("Слишком короткий домен")
    if has_numbers_in_domain(url):
        explanations.append("Много цифр в домене")
    if has_many_subdomains(url):
        explanations.append("Много поддоменов")
    if is_suspicious_tld(url):
        explanations.append("Подозрительная доменная зона")
    if has_brand_phishing(url):
        explanations.append("Известный бренд в подозрительном контексте")
    if is_ip_with_port(url):
        explanations.append("IP-адрес с портом")
    
    if not explanations:
        explanations.append("Явных признаков фишинга не обнаружено")
    
    result = {
        'url': raw_url,
        'normalized_url': url,
        'verdict': verdict,
        'verdict_text': verdict_text,
        'score': round(score * 100),
        'explanations': explanations[:10]
    }
    
    set_cached(url, result)
    return jsonify(result)

@app.route('/feedback', methods=['POST'])
def feedback():
    data = request.json
    os.makedirs('data', exist_ok=True)
    try:
        conn = sqlite3.connect('data/feedback.db')
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS feedbacks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT,
                model_verdict TEXT,
                user_verdict TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cursor.execute(
            'INSERT INTO feedbacks (url, model_verdict, user_verdict) VALUES (?, ?, ?)',
            (data.get('url'), data.get('model_verdict'), data.get('user_verdict'))
        )
        conn.commit()
        conn.close()
        return jsonify({'status': 'ok'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/admin/feedbacks')
def admin_feedbacks():
    try:
        conn = sqlite3.connect('data/feedback.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM feedbacks ORDER BY timestamp DESC LIMIT 100')
        rows = cursor.fetchall()
        conn.close()
        
        if not rows:
            return '<h1>Отзывов нет</h1><a href="/">Главная</a>'
        
        html = '''
        <style>
        body { font-family: Arial; margin: 40px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; }
        th { background: #f2f2f2; }
        .match { color: green; }
        .error { color: red; font-weight: bold; }
        </style>
        <h1>Отзывы ({len(rows)})</h1>
        <table>
        <tr><th>ID</th><th>URL</th><th>Модель</th><th>Пользователь</th><th>Дата</th></tr>
        '''
        
        for row in rows:
            match_class = 'match' if row[2] == row[3] else 'error'
            url_short = (row[1][:50] + '...') if len(row[1]) > 50 else row[1]
            html += f'''
            <tr>
                <td>{row[0]}</td>
                <td style="max-width:200px;word-break:break-all"><a href="{row[1]}" target="_blank">{url_short}</a></td>
                <td>{row[2]}</td>
                <td class="{match_class}">{row[3]}</td>
                <td>{row[4]}</td>
            </tr>
            '''
        
        html += '</table><a href="/">Главная</a>'
        return html
        
    except Exception as e:
        return f"<h1>Ошибка: {e}</h1><a href='/'>Главная</a>"

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
