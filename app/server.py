import sys
import json
import sqlite3
import os
import re
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify
import pandas as pd
import joblib

print("=== SERVER STARTING ===", file=sys.stderr)
sys.stderr.flush()

app = Flask(__name__)

# ========== НОРМАЛИЗАЦИЯ И ВАЛИДАЦИЯ ==========

def normalize_url(url):
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    url = url.lower()
    url = url.rstrip('/')
    return url

def is_valid_url(url):
    if not url:
        return False
    if not url.startswith(('http://', 'https://')):
        return False
    if ' ' in url:
        return False
    try:
        domain_part = url.split('/')[2]
        if ':' in domain_part:
            domain_part = domain_part.split(':')[0]
        
        if '.' not in domain_part:
            return False
        
        ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        if ip_pattern.match(domain_part):
            return True
        
        invalid_chars = [',', ';', '|', '\\', '^', '`', '[', ']', '{', '}', '<', '>', '"', "'"]
        for char in invalid_chars:
            if char in domain_part:
                return False
        domain_pattern = re.compile(r'^[a-z0-9.-]+$')
        if not domain_pattern.match(domain_part):
            return False
    except:
        return False
    return True

# ========== ПРОВЕРКИ ==========

def has_homoglyphs(url):
    dangerous_chars = ['а', 'е', 'о', 'р', 'с', 'у', 'х']
    for char in url.lower():
        if char in dangerous_chars:
            return True
    return False

def has_encoding(url):
    return bool(re.search(r'%[0-9A-Fa-f]{2}', url))

def has_suspicious_path(url):
    suspicious_paths = ['login', 'verify', 'secure', 'account', 'banking', 'payment', 'update', 'confirm']
    try:
        path_parts = url.split('/')[3:]
        for part in path_parts:
            for word in suspicious_paths:
                if word in part.lower():
                    return True
    except:
        pass
    return False

def has_suspicious_params(url):
    suspicious_params = ['redirect', 'url', 'return', 'next', 'goto', 'target', 'redir']
    if '?' in url:
        params = url.split('?')[1]
        for param in suspicious_params:
            if param + '=' in params.lower():
                return True
    return False

def is_short_domain(url):
    """Проверяет, что домен очень короткий (подозрительно)"""
    try:
        domain = url.split('/')[2]
        if ':' in domain:
            domain = domain.split(':')[0]
        main_part = domain.split('.')[0]
        
        # Легитимные короткие домены (не считать подозрительными)
        legitimate_short = ['ya', 'vk', 'ok', 'fb', 'gg', 'go', 'im', 'tv', 'io', 'ru', 'com']
        if main_part in legitimate_short:
            return False
            
        return len(main_part) <= 3
    except:
        return False

def has_numbers_in_domain(url):
    try:
        domain = url.split('/')[2]
        if ':' in domain:
            domain = domain.split(':')[0]
        digits = sum(c.isdigit() for c in domain)
        return digits > 5
    except:
        return False

def has_many_subdomains(url):
    try:
        domain = url.split('/')[2]
        if ':' in domain:
            domain = domain.split(':')[0]
        subdomains = domain.split('.')[:-2]
        return len(subdomains) > 3
    except:
        return False

def is_localhost(url):
    local_patterns = [
        r'localhost',
        r'127\.0\.0\.1',
        r'192\.168\.\d{1,3}\.\d{1,3}',
        r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    ]
    for pattern in local_patterns:
        if re.search(pattern, url):
            return True
    return False

def is_typosquatting(url):
    popular_domains = ['google', 'facebook', 'youtube', 'vk', 'mail', 'yandex', 'gmail', 'yahoo', 'instagram', 'twitter', 'whatsapp', 'telegram', 'github']
    try:
        domain = url.split('/')[2].lower()
        if ':' in domain:
            domain = domain.split(':')[0]
        for popular in popular_domains:
            if popular in domain and popular != domain:
                if len(domain) > len(popular) + 1:
                    return True
                suspicious = domain.replace('0', 'o').replace('1', 'l').replace('5', 's').replace('@', 'a')
                if popular in suspicious and popular != suspicious:
                    return True
    except:
        pass
    return False

def is_suspicious_tld(url):
    suspicious_tlds = ['.xyz', '.top', '.club', '.online', '.site', '.pw', '.cc', '.tk', '.ml', '.ga', '.cf', '.bid', '.win', '.download', '.pro', '.work']
    for tld in suspicious_tlds:
        if tld in url:
            return True
    return False

def has_redirects(url):
    try:
        if 'redirect=' in url or 'url=' in url or 'return=' in url or 'next=' in url or 'goto=' in url:
            return True
    except:
        pass
    return False

def is_too_long(url):
    return len(url) > 200

def has_brand_phishing(url):
    """Проверяет наличие известных брендов в фишинговом контексте"""
    brands = [
        'paypal', 'wellsfargo', 'google', 'apple', 'microsoft', 
        'amazon', 'facebook', 'instagram', 'bank', 'sberbank',
        'vtb', 'tinkoff', 'alfabank', 'yahoo', 'gmail'
    ]
    try:
        url_lower = url.lower()
        for brand in brands:
            if brand in url_lower:
                legitimate = ['paypal.com', 'google.com', 'apple.com', 'microsoft.com', 'amazon.com']
                is_legitimate = any(l in url_lower for l in legitimate)
                if not is_legitimate:
                    return True
    except:
        pass
    return False

def is_ip_with_port(url):
    ip_pattern = re.compile(r'https?://(\d{1,3}\.){3}\d{1,3}:\d+')
    return bool(ip_pattern.match(url))

def has_suspicious_domain_pattern(url):
    try:
        domain = url.split('/')[2].lower()
        if ':' in domain:
            domain = domain.split(':')[0]
        if domain.count('-') > 3:
            return True
        if domain.count('.') > 4:
            return True
        if re.search(r'[bcdfghjklmnpqrstvwxyz]{6,}', domain):
            return True
    except:
        pass
    return False

# ========== ЗАГРУЗКА МОДЕЛИ ==========

print("Loading features and model...", file=sys.stderr)
sys.stderr.flush()

try:
    features_df = pd.read_csv('data/processed/url_dataset_features.csv')
    feature_columns = [col for col in features_df.columns if col not in ['url', 'label']]
    print(f"Загружено {len(features_df)} записей, {len(feature_columns)} признаков", file=sys.stderr)
    model = joblib.load('ml/model.pkl')
    print("Модель успешно загружена", file=sys.stderr)
except Exception as e:
    print(f"Ошибка загрузки модели: {e}", file=sys.stderr)
    features_df = None
    feature_columns = []
    model = None

sys.stderr.flush()

cache = {}

def get_cached(url):
    if url in cache:
        data, timestamp = cache[url]
        if datetime.now() - timestamp < timedelta(hours=1):
            return data
        else:
            del cache[url]
    return None

def set_cached(url, data):
    cache[url] = (data, datetime.now())

# ========== РОУТЫ ==========

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/health')
def health():
    return jsonify({
        'status': 'ok',
        'model_loaded': model is not None and features_df is not None
    })

@app.route('/check', methods=['POST'])
def check_url():
    data = request.json
    raw_url = data.get('url')
    
    if not raw_url:
        return jsonify({'error': 'URL не указан'}), 400
    
    url = normalize_url(raw_url)
    
    if not is_valid_url(url):
        return jsonify({
            'url': raw_url,
            'verdict': 'invalid',
            'verdict_text': '❌ НЕВАЛИДНЫЙ URL',
            'score': 0,
            'explanations': [
                'URL должен начинаться с http:// или https://',
                'URL не должен содержать пробелов',
                'Пример: https://google.com'
            ]
        }), 400
    
    if is_localhost(url):
        return jsonify({
            'url': url,
            'verdict': 'warning',
            'verdict_text': '⚠️ ЛОКАЛЬНЫЙ АДРЕС',
            'score': 0,
            'explanations': ['Локальные адреса (localhost, 192.168.x.x) не проверяются']
        })
    
    cached = get_cached(url)
    if cached:
        return jsonify(cached)
    
    try:
        if model is None or features_df is None:
            raise Exception("Модель или признаки не загружены")
        
        url_row = features_df[features_df['url'] == url]
        
        if url_row.empty:
            print(f"URL не найден в датасете: {url}", file=sys.stderr)
            score = 0.3
            if 'login' in url.lower() or 'verify' in url.lower() or 'secure' in url.lower():
                score = 0.8
            elif 'bit.ly' in url.lower() or 'goo.gl' in url.lower() or 'tinyurl' in url.lower():
                score = 0.6
        else:
            X = url_row[feature_columns]
            score = model.predict_proba(X)[0][1]
            print(f"Предсказание для {url}: score={score:.2f}", file=sys.stderr)
        
    except Exception as e:
        print(f"Ошибка при анализе URL {url}: {e}", file=sys.stderr)
        score = 0.3
        if 'login' in url.lower() or 'verify' in url.lower() or 'secure' in url.lower():
            score = 0.8
        elif 'bit.ly' in url.lower() or 'goo.gl' in url.lower() or 'tinyurl' in url.lower():
            score = 0.6
    
    # Корректировка score для подозрительных случаев
    if score < 0.4:
        if has_numbers_in_domain(url):
            score = 0.45
            print(f"Повышаю score из-за цифр в домене: {url}", file=sys.stderr)
        elif is_short_domain(url):
            score = 0.45
            print(f"Повышаю score из-за короткого домена: {url}", file=sys.stderr)
        elif has_many_subdomains(url):
            score = 0.45
            print(f"Повышаю score из-за множества поддоменов: {url}", file=sys.stderr)
        elif is_suspicious_tld(url):
            score = 0.45
            print(f"Повышаю score из-за подозрительного TLD: {url}", file=sys.stderr)
    
    if has_brand_phishing(url) and score < 0.7:
        score = 0.75
        print(f"Повышаю score из-за бренда в фишинговом контексте: {url}", file=sys.stderr)
    
    if is_ip_with_port(url):
        score = 0.8
        print(f"Повышаю score из-за IP с портом: {url}", file=sys.stderr)
    
    if has_suspicious_domain_pattern(url) and score < 0.5:
        score = 0.55
        print(f"Повышаю score из-за подозрительного паттерна домена: {url}", file=sys.stderr)
    
    # Вердикт на основе score
    if score > 0.7:
        verdict = "dangerous"
        verdict_text = "🔴 ОПАСНО"
    elif score > 0.4:
        verdict = "suspicious"
        verdict_text = "🟡 ПОДОЗРИТЕЛЬНО"
    else:
        verdict = "safe"
        verdict_text = "🟢 БЕЗОПАСНО"
    
    # Объяснения
    explanations = []
    
    if not url.startswith('https'):
        explanations.append("Отсутствует защищенное соединение HTTPS")
    
    if 'login' in url.lower() or 'verify' in url.lower() or 'secure' in url.lower():
        explanations.append("Обнаружены подозрительные слова (login, verify, secure)")
    
    if 'bit.ly' in url.lower() or 'goo.gl' in url.lower() or 'tinyurl' in url.lower():
        explanations.append("Использован сервис сокращения ссылок")
    
    ip_pattern = re.compile(r'https?://(\d{1,3}\.){3}\d{1,3}')
    if ip_pattern.match(url):
        explanations.append("Ссылка содержит IP-адрес вместо доменного имени")
    
    if '@' in url:
        explanations.append("Ссылка содержит символ @ (может использоваться для обмана)")
    
    if has_homoglyphs(url):
        explanations.append("Ссылка содержит символы, похожие на латиницу (омоглифы)")
    
    if has_encoding(url):
        explanations.append("Ссылка содержит закодированные символы (%XX)")
    
    if has_suspicious_path(url):
        explanations.append("В пути ссылки обнаружены подозрительные слова")
    
    if has_suspicious_params(url):
        explanations.append("Ссылка содержит подозрительные параметры перенаправления")
    
    if is_short_domain(url):
        explanations.append("Домен слишком короткий (часто используется в фишинге)")
    
    if has_numbers_in_domain(url):
        explanations.append("Домен содержит много цифр (подозрительно)")
    
    if has_many_subdomains(url):
        explanations.append("Слишком много поддоменов (попытка запутать)")
    
    if is_typosquatting(url):
        explanations.append("Ссылка имитирует домен известного сайта")
    
    if is_suspicious_tld(url):
        explanations.append("Использована подозрительная доменная зона")
    
    if has_redirects(url):
        explanations.append("Ссылка содержит параметры перенаправления")
    
    if is_too_long(url):
        explanations.append("Ссылка слишком длинная (более 200 символов)")
    
    if has_brand_phishing(url):
        explanations.append("Ссылка использует имя известного бренда для обмана")
    
    if is_ip_with_port(url):
        explanations.append("Ссылка ведет на IP-адрес с портом (часто используется в фишинге)")
    
    if has_suspicious_domain_pattern(url):
        explanations.append("Домен имеет подозрительную структуру (много дефисов или случайные символы)")
    
    if not explanations:
        explanations.append("Явных признаков фишинга не обнаружено")
    
    result = {
        'url': raw_url,
        'verdict': verdict,
        'verdict_text': verdict_text,
        'score': round(score * 100),
        'explanations': explanations
    }
    
    set_cached(url, result)
    return jsonify(result)

@app.route('/feedback', methods=['POST'])
def feedback():
    data = request.json
    
    os.makedirs('data', exist_ok=True)
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
    conn.commit()
    cursor.execute(
        'INSERT INTO feedbacks (url, model_verdict, user_verdict) VALUES (?, ?, ?)',
        (data['url'], data['model_verdict'], data['user_verdict'])
    )
    conn.commit()
    conn.close()
    
    return jsonify({'status': 'ok'})

@app.route('/admin/feedbacks')
def admin_feedbacks():
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
        conn.commit()
        cursor.execute('SELECT * FROM feedbacks ORDER BY timestamp DESC LIMIT 100')
        rows = cursor.fetchall()
        conn.close()
        
        if not rows:
            return '''
            <html><body>
            <h1>📋 Отзывы пользователей</h1>
            <p>📭 Пока нет отзывов. Нажмите "Сообщить об ошибке" на сайте.</p>
            <a href="/">На главную</a>
            </body></html>
            '''
        
        html = '<h1>📋 Отзывы пользователей</h1>'
        html += f'<p>Всего отзывов: {len(rows)}</p>'
        html += '<table border="1" cellpadding="5">'
        html += ' octet-stream<th>ID</th><th>URL</th><th>Модель</th><th>Пользователь</th><th>Дата</th> 项'
        
        for row in rows:
            match_style = 'color: green;' if row[2] == row[3] else 'color: red; font-weight: bold;'
            html += f'''
            <tr>
                <td>{row[0]}项
                <td style="word-break: break-all; max-width: 400px;">{row[1][:80]}{'...' if len(row[1]) > 80 else ''}项
                <td>{row[2]}项
                <td style="{match_style}">{row[3]}项
                <td>{row[4]}项
             '
            '''
        
        html += '赶<a href="/">На главную</a>'
        return html
        
    except Exception as e:
        return f"<h1>Ошибка</h1><p>{str(e)}</p><a href='/'>На главную</a>", 500

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
