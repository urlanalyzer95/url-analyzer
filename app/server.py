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
        domain = url.split('/')[2]
        if '.' not in domain:
            return False
        # Проверка на недопустимые символы в домене
        invalid_chars = [',', ';', '|', '\\', '^', '`', '[', ']', '{', '}', '<', '>', '"', "'"]
        for char in invalid_chars:
            if char in domain:
                return False
        domain_pattern = re.compile(r'^[a-z0-9.-]+$')
        if not domain_pattern.match(domain):
            return False
    except:
        return False
    return True

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
    popular_domains = ['google', 'facebook', 'youtube', 'vk', 'mail', 'yandex', 'gmail', 'yahoo']
    try:
        domain = url.split('/')[2].lower()
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
    suspicious_tlds = ['.xyz', '.top', '.club', '.online', '.site', '.pw', '.cc', '.tk', '.ml', '.ga', '.cf']
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

print("Loading features and model...", file=sys.stderr)
sys.stderr.flush()

try:
    features_df = pd.read_csv('data/processed/url_dataset_features.csv')
    feature_columns = [col for col in features_df.columns if col not in ['url', 'label']]
    print(f"✅ Загружено {len(features_df)} записей, {len(feature_columns)} признаков", file=sys.stderr)
    model = joblib.load('ml/model.pkl')
    print("✅ Model loaded successfully", file=sys.stderr)
except Exception as e:
    print(f"❌ Error loading features or model: {e}", file=sys.stderr)
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
            print(f"⚠️ URL не найден в датасете: {url}", file=sys.stderr)
            score = 0.3
            if 'login' in url.lower() or 'verify' in url.lower() or 'secure' in url.lower():
                score = 0.8
            elif 'bit.ly' in url.lower() or 'goo.gl' in url.lower() or 'tinyurl' in url.lower():
                score = 0.6
        else:
            X = url_row[feature_columns]
            score = model.predict_proba(X)[0][1]
            print(f"✅ Предсказание для {url}: score={score:.2f}", file=sys.stderr)
        
    except Exception as e:
        print(f"⚠️ Ошибка при анализе URL {url}: {e}", file=sys.stderr)
        score = 0.3
        if 'login' in url.lower() or 'verify' in url.lower() or 'secure' in url.lower():
            score = 0.8
        elif 'bit.ly' in url.lower() or 'goo.gl' in url.lower() or 'tinyurl' in url.lower():
            score = 0.6
    
    if score > 0.7:
        verdict = "dangerous"
        verdict_text = "🔴 ОПАСНО"
    elif score > 0.4:
        verdict = "suspicious"
        verdict_text = "🟡 ПОДОЗРИТЕЛЬНО"
    else:
        verdict = "safe"
        verdict_text = "🟢 БЕЗОПАСНО"
    
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
        explanations.append("Ссылка содержит символ @ (может использоваться для обмана")
    
    if is_typosquatting(url):
        explanations.append("Ссылка имитирует домен известного сайта")
    
    if is_suspicious_tld(url):
        explanations.append("Использована подозрительная доменная зона")
    
    if has_redirects(url):
        explanations.append("Ссылка содержит параметры перенаправления")
    
    if is_too_long(url):
        explanations.append("Ссылка слишком длинная (более 200 символов)")
    
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
        cursor.execute('SELECT * FROM feedbacks ORDER BY timestamp DESC LIMIT 100')
        rows = cursor.fetchall()
        conn.close()

        # Простой вывод без сложного форматирования
        html = '<h1>Отзывы пользователей</h1>'
        if not rows:
            html += '<p>Пока нет отзывов. Нажмите "Сообщить об ошибке" на сайте.</p>'
        else:
            html += f'<p>Всего отзывов: {len(rows)}</p>'
            html += '<ul>'
            for row in rows:
                html += f'<li><b>{row[4]}</b> | URL: {row[1][:50]} | Модель: {row[2]} | Пользователь: {row[3]}</li>'
            html += '</ul>'
        html += '<p><a href="/">На главную</a></p>'
        return html
    except Exception as e:
        return f'<h1>Ошибка</h1><p>{str(e)}</p><p><a href="/">На главную</a></p>', 500

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
