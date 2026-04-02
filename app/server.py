import sys
import json
import sqlite3
import os
import re
from datetime import datetime, timedelta
from urllib.parse import urlparse
from flask import Flask, render_template, request, jsonify
import pandas as pd
import joblib
from pathlib import Path

ROOT_DIR = Path(__file__).parent.parent
SRC_DIR = ROOT_DIR / 'src'

print(f"ROOT_DIR: {ROOT_DIR}", file=sys.stderr)
print(f"SRC_DIR: {SRC_DIR}", file=sys.stderr)
print(f"SRC_DIR exists: {SRC_DIR.exists()}", file=sys.stderr)
print(f"Files in SRC_DIR: {list(SRC_DIR.glob('*.py'))}", file=sys.stderr)

sys.path.insert(0, str(SRC_DIR))

try:
    from feedback_system import FeedbackSystem
    feedback_system = FeedbackSystem()
    print("✅ FeedbackSystem загружена", file=sys.stderr)
except Exception as e:
    print(f"⚠️ FeedbackSystem не загружена: {e}", file=sys.stderr)
    feedback_system = None

print("=== SERVER STARTING ===", file=sys.stderr)
sys.stderr.flush()

app = Flask(__name__)

cache = {}

def get_cached(url):
    if url in cache:
        data, timestamp = cache[url]
        if datetime.now() - timestamp < timedelta(hours=1):
            return data
        del cache[url]
    return None

def set_cached(url, data):
    cache[url] = (data, datetime.now())

def normalize_url(url):
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return url.lower().rstrip('/')

def is_valid_url(url):
    if not url.startswith(('http://', 'https://')) or ' ' in url:
        return False
    try:
        netloc = urlparse(url).netloc.split(':')[0]
        return '.' in netloc
    except:
        return False

def is_localhost(url):
    return bool(re.search(r'localhost|127\.0\.0\.1|192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}', url))

def has_suspicious_path(url):
    words = ['login', 'verify', 'secure', 'account', 'banking', 'payment', 'update', 'confirm', 'servicee']
    path = urlparse(url).path.lower()
    return any(w in path for w in words)

def has_suspicious_params(url):
    params = ['redirect', 'url', 'return', 'next', 'goto', 'target']
    query = urlparse(url).query.lower()
    return any(p + '=' in query for p in params)

def is_short_domain(url):
    try:
        domain = urlparse(url).netloc.split(':')[0]
        main = domain.split('.')[0]
        legitimate = ['ya', 'vk', 'ok', 'fb', 'gg', 'go', 'im', 'tv', 'io', 'ru', 'com']
        return main not in legitimate and len(main) <= 3
    except:
        return False

def has_numbers_in_domain(url):
    try:
        domain = urlparse(url).netloc.split(':')[0]
        return sum(c.isdigit() for c in domain) > 5
    except:
        return False

def has_many_subdomains(url):
    try:
        domain = urlparse(url).netloc.split(':')[0]
        return len(domain.split('.')[:-2]) > 3
    except:
        return False

def is_suspicious_tld(url):
    tlds = ['.xyz', '.top', '.club', '.online', '.site', '.pw', '.cc', '.tk', '.ml', '.ga', '.cf', '.bid', '.win']
    return any(tld in url for tld in tlds)

def is_ip_with_port(url):
    return bool(re.search(r'https?://(\d{1,3}\.){3}\d{1,3}:\d+', url))

def has_brand_phishing(url):
    brands = ['paypal', 'wellsfargo', 'google', 'apple', 'microsoft', 'amazon', 'facebook', 'instagram', 'sberbank', 'sber', 'tinkoff']
    url_lower = url.lower()
    legitimate_domains = [
        'google.com', 'yandex.ru', 'facebook.com', 'apple.com', 
        'microsoft.com', 'amazon.com', 'paypal.com', 'sberbank.ru'
    ]
    
    for legit in legitimate_domains:
        if legit in url_lower:
            return False
    
    for brand in brands:
        if brand in url_lower:
            return True
    return False

def is_typosquatting(url):
    popular = ['google', 'facebook', 'yandex', 'sberbank', 'paypal', 'wellsfargo', 'apple', 'microsoft', 'amazon']
    try:
        netloc = urlparse(url).netloc.lower().split(':')[0]
        if netloc.startswith('www.'):
            netloc = netloc[4:]
        
        legitimate_domains = [
            'google.com', 'google.ru', 'yandex.ru', 'facebook.com',
            'apple.com', 'microsoft.com', 'amazon.com', 'paypal.com'
        ]
        
        if netloc in legitimate_domains:
            return False
        
        normalized = netloc.replace('0', 'o').replace('1', 'l').replace('5', 's').replace('3', 'e').replace('4', 'a')
        for p in popular:
            if p in normalized and p not in netloc and len(netloc) > len(p):
                if any(tld in netloc for tld in ['.com', '.ru', '.org']):
                    return True
    except:
        pass
    return False

def is_shortener(url):
    shorteners = ['bit.ly', 'goo.gl', 'tinyurl', 'cutt.ly', 'clck.ru']
    return any(s in url.lower() for s in shorteners)

model = None
features_df = None
feature_columns = []

# Загрузка модели из правильного пути
try:
    model_path = Path(__file__).parent.parent / 'ml' / 'model_rf_v2.pkl'
    if model_path.exists():
        model = joblib.load(model_path)
        print("✅ Модель загружена", file=sys.stderr)
    else:
        print(f"⚠️ Модель не найдена: {model_path}", file=sys.stderr)
except Exception as e:
    print(f"⚠️ Ошибка модели: {e}", file=sys.stderr)

# Загрузка датасета из правильного пути
try:
    dataset_path = Path(__file__).parent.parent / 'data' / 'processed' / 'url_dataset_features.csv'
    if dataset_path.exists():
        features_df = pd.read_csv(dataset_path)
        feature_columns = [c for c in features_df.columns if c not in ['url', 'label']]
        print(f"✅ Датасет: {len(features_df)} записей", file=sys.stderr)
    else:
        print(f"⚠️ Датасет не найден: {dataset_path}", file=sys.stderr)
except Exception as e:
    print(f"⚠️ Ошибка датасета: {e}", file=sys.stderr)

print("🚀 Сервер готов", file=sys.stderr)
sys.stderr.flush()

def is_legitimate_domain(url):
    """Проверка, является ли URL легитимным известным сайтом"""
    legitimate_domains = [
        'google.com', 'google.ru', 'google.by',
        'yandex.ru', 'yandex.ua', 'yandex.by', 'yandex.kz',
        'github.com', 'stackoverflow.com', 'python.org',
        'facebook.com', 'apple.com', 'microsoft.com', 
        'amazon.com', 'paypal.com', 'sberbank.ru',
        'vk.com', 'ok.ru', 'mail.ru'
    ]
    
    url_lower = url.lower()
    for legit in legitimate_domains:
        if legit in url_lower and (url_lower.startswith('https://' + legit) or 
                                   url_lower.startswith('https://www.' + legit)):
            return True
    return False

def compute_score(url):
    """Вычисление уровня опасности URL (0-1)"""
    url_lower = url.lower().rstrip('/')
    
    # БЕЛЫЙ СПИСОК - ПРИОРИТЕТ
    if is_legitimate_domain(url):
        print(f"✅ Легитимный домен: {url}", file=sys.stderr)
        return 0.1
    
    signals = []
    
    # ML модель
    if model is not None and features_df is not None:
        try:
            if 'url_norm' not in features_df.columns:
                features_df['url_norm'] = features_df['url'].apply(lambda x: x.lower().rstrip('/'))
            row = features_df[features_df['url_norm'] == url_lower]
            if not row.empty:
                X = row[feature_columns]
                ml_prob = model.predict_proba(X)[0][1]
                signals.append((0.6, ml_prob))
                print(f"ML score: {ml_prob}", file=sys.stderr)
        except Exception as e:
            print(f"ML ошибка: {e}", file=sys.stderr)
    
    # Эвристики
    if not url.startswith('https'):
        signals.append((0.15, "нет HTTPS"))
    if has_brand_phishing(url):
        signals.append((0.5, "бренд"))
    if is_typosquatting(url):
        signals.append((0.45, "опечатка"))
    if is_shortener(url):
        signals.append((0.35, "сокращатель"))
    if has_suspicious_path(url):
        signals.append((0.35, "путь"))
    if has_suspicious_params(url):
        signals.append((0.3, "параметры"))
    if has_numbers_in_domain(url):
        signals.append((0.12, "цифры"))
    if is_short_domain(url):
        signals.append((0.1, "короткий домен"))
    if is_suspicious_tld(url):
        signals.append((0.3, "TLD"))
    if is_ip_with_port(url):
        signals.append((0.45, "IP с портом"))
    if has_many_subdomains(url):
        signals.append((0.12, "много поддоменов"))
    
    # Специальные вредоносные паттерны
    malicious_patterns = ['/servicee/', '/update.php', '/house-sites/', '/cgi-bin/']
    for pattern in malicious_patterns:
        if pattern in url_lower:
            signals.append((0.25, "вредоносный паттерн"))
    
    # Комбинации признаков
    no_https = not url.startswith('https')
    suspicious_path = has_suspicious_path(url)
    brand_phish = has_brand_phishing(url)
    
    if no_https and suspicious_path:
        signals.append((0.2, "нет HTTPS + подозрительный путь"))
    if no_https and brand_phish:
        signals.append((0.25, "нет HTTPS + имитация бренда"))
    if suspicious_path and brand_phish:
        signals.append((0.2, "подозрительный путь + бренд"))
    
    if not signals:
        signals.append((0.05, "нет признаков"))
    
    total = sum(w for w, _ in signals)
    total = min(total, 1.0)
    
    print(f"Final score: {total}", file=sys.stderr)
    return total

def get_explanations(url):
    """Получение объяснений для пользователя"""
    exps = []
    url_lower = url.lower()
    
    if is_legitimate_domain(url):
        return ["✅ Известный доверенный сайт"]
    
    if not url.startswith('https'):
        exps.append("Отсутствует защищённое соединение HTTPS")
    if is_shortener(url):
        exps.append("Сервис сокращения ссылок")
    if has_brand_phishing(url):
        exps.append("Ссылка использует имя известного бренда для обмана")
    if is_typosquatting(url):
        exps.append("Ссылка имитирует домен известного сайта")
    if has_suspicious_path(url):
        exps.append("В пути ссылки обнаружены подозрительные слова")
    if has_suspicious_params(url):
        exps.append("Ссылка содержит подозрительные параметры перенаправления")
    if has_numbers_in_domain(url):
        exps.append("Домен содержит много цифр")
    if is_short_domain(url):
        exps.append("Слишком короткий домен")
    if is_suspicious_tld(url):
        exps.append("Подозрительная доменная зона")
    if is_ip_with_port(url):
        exps.append("IP-адрес с портом")
    if has_many_subdomains(url):
        exps.append("Слишком много поддоменов")
    
    malicious_patterns = ['/servicee/', '/update.php', '/house-sites/']
    for pattern in malicious_patterns:
        if pattern in url_lower:
            exps.append("Обнаружен вредоносный паттерн в URL")
            break
    
    if not exps:
        exps.append("Явных признаков фишинга не обнаружено")
    
    return exps

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/health')
def health():
    return jsonify({
        'status': 'ok',
        'model_loaded': model is not None,
        'model_version': 'v2.0',
        'model_accuracy': '98.5%'
    })

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
            'verdict_text': '❌ НЕВАЛИДНЫЙ URL',
            'score': 0,
            'explanations': ['URL должен начинаться с http:// или https://', 'URL не должен содержать пробелов']
        }), 400

    if is_localhost(url):
        return jsonify({
            'url': url,
            'verdict': 'warning',
            'verdict_text': '⚠️ ЛОКАЛЬНЫЙ АДРЕС',
            'score': 0,
            'explanations': ['Локальные адреса не проверяются']
        })

    cached = get_cached(url)
    if cached:
        return jsonify(cached)

    score = compute_score(url)

    if score > 0.7:
        verdict, text = "dangerous", "🔴 ОПАСНО"
    elif score > 0.4:
        verdict, text = "suspicious", "🟡 ПОДОЗРИТЕЛЬНО"
    else:
        verdict, text = "safe", "🟢 БЕЗОПАСНО"

    result = {
        'url': raw_url,
        'verdict': verdict,
        'verdict_text': text,
        'score': round(score * 100),
        'explanations': get_explanations(url)
    }

    set_cached(url, result)
    return jsonify(result)

@app.route('/feedback', methods=['POST'])
def feedback():
    """Обработка обратной связи"""
    try:
        data = request.json
        print(f"📝 Получен feedback: {data}", file=sys.stderr)
        
        if feedback_system is None:
            print("❌ FeedbackSystem не инициализирован", file=sys.stderr)
            try:
                os.makedirs('data', exist_ok=True)
                conn = sqlite3.connect('data/feedback.db')
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS feedbacks (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        url TEXT,
                        model_verdict TEXT,
                        user_verdict TEXT,
                        user_comment TEXT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                conn.execute('''
                    INSERT INTO feedbacks (url, model_verdict, user_verdict, user_comment) 
                    VALUES (?, ?, ?, ?)
                ''', (
                    data.get('url', ''),
                    data.get('model_verdict', ''),
                    data.get('user_verdict', ''),
                    data.get('comment', '')
                ))
                conn.commit()
                conn.close()
                print("✅ Feedback сохранён через fallback", file=sys.stderr)
                return jsonify({'status': 'ok', 'message': 'Спасибо за отзыв!'})
            except Exception as fallback_error:
                print(f"❌ Fallback ошибка: {fallback_error}", file=sys.stderr)
                return jsonify({'status': 'error', 'error': 'Система обратной связи недоступна'}), 500
        
        success = feedback_system.add_feedback(
            url=data.get('url', ''),
            model_verdict=data.get('model_verdict', ''),
            user_verdict=data.get('user_verdict', ''),
            user_comment=data.get('comment', '')
        )
        
        if success:
            print("✅ Feedback сохранён", file=sys.stderr)
            return jsonify({'status': 'ok', 'message': 'Спасибо за отзыв!'})
        else:
            print("❌ Ошибка при сохранении", file=sys.stderr)
            return jsonify({'status': 'error', 'error': 'Ошибка сохранения'}), 500
            
    except Exception as e:
        print(f"❌ Ошибка в /feedback: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        return jsonify({'status': 'error', 'error': str(e)}), 500

@app.route('/admin/feedbacks')
def admin_feedbacks():
    """Админка для просмотра отзывов"""
    try:
        if feedback_system is None:
            try:
                conn = sqlite3.connect('data/feedback.db')
                df = pd.read_sql_query("SELECT * FROM feedbacks ORDER BY timestamp DESC LIMIT 100", conn)
                conn.close()
                
                if df.empty:
                    return '<h1>📋 Отзывы</h1><p>Пока нет отзывов</p><p><a href="/">На главную</a></p>'
                
                html = '<h1>📋 Отзывы</h1><p><a href="/">← На главную</a></p>'
                html += '<table border="1" cellpadding="5">'
                html += '<tr><th>ID</th><th>URL</th><th>Модель</th><th>Пользователь</th><th>Комментарий</th><th>Дата</th></tr>'
                
                for _, row in df.iterrows():
                    html += '<tr>'
                    html += f'<td>{row["id"]}</td>'
                    html += f'<td style="max-width:400px; word-break:break-all;">{row["url"][:80]}</td>'
                    html += f'<td>{row["model_verdict"]}</td>'
                    html += f'<td>{row["user_verdict"]}</td>'
                    html += f'<td>{row.get("user_comment", "-")}</td>'
                    html += f'<td>{row["timestamp"]}</td>'
                    html += '</tr>'
                
                html += '</table><p><a href="/">На главную</a></p>'
                return html
                
            except Exception as e:
                return f'<h1>❌ Ошибка</h1><p>{e}</p><p><a href="/">На главную</a></p>'
        
        df = feedback_system.get_all_feedback(limit=100)
        
        if df.empty:
            return '<h1>📋 Отзывы</h1><p>Пока нет отзывов</p><p><a href="/">На главную</a></p>'
        
        html = '<h1>📋 Отзывы</h1><p><a href="/">← На главную</a></p>'
        html += '<table border="1" cellpadding="5">'
        html += '<tr style="background-color: #4CAF50; color: white;">'
        html += '<th>ID</th><th>URL</th><th>Модель</th><th>Пользователь</th><th>Комментарий</th><th>Дата</th></tr>'
        
        for _, row in df.iterrows():
            style = ''
            if row['model_verdict'] != row['user_verdict'] and row['user_verdict'] != 'other':
                style = 'style="background-color: #ffebee;"'
            
            html += f'<tr {style}>'
            html += f'<td>{row["id"]}</td>'
            html += f'<td style="max-width:400px; word-break:break-all;">{row["url"][:80]}</td>'
            html += f'<td>{row["model_verdict"]}</td>'
            
            user_style = ''
            if row['user_verdict'] == 'dangerous':
                user_style = 'style="color: red; font-weight: bold;"'
            elif row['user_verdict'] == 'safe':
                user_style = 'style="color: green; font-weight: bold;"'
            
            html += f'<td {user_style}>{row["user_verdict"]}</td>'
            html += f'<td>{row.get("user_comment", "-")}</td>'
            html += f'<td>{row["timestamp"]}</td>'
            html += '</tr>'
        
        html += '</table>'
        
        try:
            stats = feedback_system.get_stats()
            html += f'''
            <hr>
            <h3>📊 Статистика</h3>
            <p>Всего отзывов: {stats["total_feedback"]}</p>
            <p>Расхождений: {stats["mismatches"]}</p>
            <p>Точность: {stats["accuracy_estimate"]}%</p>
            '''
        except:
            pass
        
        html += '<p><a href="/">На главную</a></p>'
        return html
        
    except Exception as e:
        import traceback
        return f'<h1>❌ Ошибка</h1><pre>{traceback.format_exc()}</pre><p><a href="/">На главную</a></p>'

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=False)