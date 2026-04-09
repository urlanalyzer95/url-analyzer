import sys
import os
import re
from datetime import datetime, timedelta
from urllib.parse import urlparse
from pathlib import Path

import pandas as pd
import joblib
from flask import Flask, render_template, request, jsonify, send_file

# Импорт модуля БД
try:
    from db import init_db, save_feedback, get_all_feedbacks, get_db_path
except ImportError:
    from app.db import init_db, save_feedback, get_all_feedbacks, get_db_path

# Импорт извлечения признаков (после загрузки модели)
from ml.features import extract_features

app = Flask(__name__, template_folder='templates')
cache = {}

# Белый список доверенных доменов
TRUSTED_DOMAINS = [
    'google.com', 'yandex.ru', 'github.com', 'stackoverflow.com',
    'vk.com', 'wikipedia.org', 'youtube.com', 'instagram.com',
    'facebook.com', 'twitter.com', 'amazon.com', 'apple.com',
    'microsoft.com', 'reddit.com', 'linkedin.com'
]

def is_trusted(url):
    try:
        domain = urlparse(url).netloc
        if domain.startswith('www.'):
            domain = domain[4:]
        return any(domain == d or domain.endswith('.' + d) for d in TRUSTED_DOMAINS)
    except:
        return False

# Инициализация БД
init_db()

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

def get_cached(url):
    if url in cache:
        data, timestamp = cache[url]
        if datetime.now() - timestamp < timedelta(hours=24):
            return data
        del cache[url]
    return None

def set_cached(url, data):
    cache[url] = (data, datetime.now())

# Загрузка модели и датасета
model = None
feature_columns = []
features_df = None
BASE_DIR = Path(__file__).parent.parent

try:
    model_path = BASE_DIR / 'ml' / 'model.pkl'
    if model_path.exists():
        model = joblib.load(model_path)
        print(f"✅ Модель загружена из {model_path}", file=sys.stderr)

    dataset_path = BASE_DIR / 'data' / 'processed' / 'url_dataset_features.csv'
    if dataset_path.exists():
        features_df = pd.read_csv(dataset_path)
        feature_columns = [c for c in features_df.columns if c not in ['url', 'label']]
        print(f"✅ Датасет загружен: {len(features_df)} записей", file=sys.stderr)
except Exception as e:
    print(f"⚠️ Ошибка загрузки: {e}", file=sys.stderr)

def predict(url):
    if model is None:
        return 0.5

    try:
        url_lower = url.lower().rstrip('/')

        # 1. Поиск в датасете
        if features_df is not None and feature_columns:
            if 'url_norm' not in features_df.columns:
                features_df['url_norm'] = features_df['url'].apply(
                    lambda x: str(x).lower().rstrip('/') if pd.notna(x) else ''
                )
            row = features_df[features_df['url_norm'] == url_lower]
            if not row.empty:
                X = row[feature_columns]
                proba = model.predict_proba(X)[0][1]
                return float(proba)

        # 2. Эвристики
        if re.search(r'\d{1,3}(\.\d{1,3}){3}', url_lower):
            return 0.95                     # IP-адрес → опасность 95%

        shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly']
        if any(s in url_lower for s in shorteners):
            return 0.70                     # Короткая ссылка → подозрительно 70%

        # 3. ML модель
        features = extract_features(url)
        features_df_input = pd.DataFrame([features], columns=feature_columns)
        proba = model.predict_proba(features_df_input)[0][1]

        # Ограничение для подозрительных слов (максимум 70%)
        suspicious_words = ['login', 'verify', 'account', 'secure', 'update', 'confirm', 'signin']
        if any(word in url_lower for word in suspicious_words):
            proba = min(proba, 0.70)

        return float(proba)
    except Exception as e:
        print(f"ML ошибка: {e}", file=sys.stderr)
        return 0.5

# ---------- Эндпоинты ----------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/health')
def health():
    return jsonify({
        'status': 'ok',
        'model_loaded': model is not None,
        'model_version': 'v2.0'
    })

@app.route('/check', methods=['POST'])
def check_url():
    data = request.json
    raw_url = data.get('url', '').strip()
    if not raw_url:
        return jsonify({'error': 'URL не указан'}), 400

    url = normalize_url(raw_url)
    if not is_valid_url(url):
        return jsonify({'error': 'Невалидный URL'}), 400

    cached = get_cached(url)
    if cached:
        return jsonify(cached)

    # Белый список
    if is_trusted(url):
        result = {
            'url': raw_url,
            'verdict': 'safe',
            'verdict_text': '🟢 БЕЗОПАСНО',
            'score': 0,
            'explanations': ['Домен из списка доверенных']
        }
        set_cached(url, result)
        return jsonify(result)

    score = predict(url)
    if score > 0.9:
        verdict, text = "dangerous", "🔴 ОПАСНО"
    elif score > 0.5:
        verdict, text = "suspicious", "🟡 ПОДОЗРИТЕЛЬНО"
    else:
        verdict, text = "safe", "🟢 БЕЗОПАСНО"

    result = {
        'url': raw_url,
        'verdict': verdict,
        'verdict_text': text,
        'score': round(score * 100),
        'explanations': ["ML модель определила уровень опасности"]
    }
    set_cached(url, result)
    return jsonify(result)

@app.route('/feedback', methods=['POST'])
def feedback():
    try:
        data = request.json
        url = data.get('url', '').strip()
        model_verdict = data.get('model_verdict', '')
        user_verdict = data.get('user_verdict', '')
        comment = data.get('comment', '')

        if url:
            try:
                normalized = normalize_url(url)
                if not is_valid_url(normalized):
                    model_verdict = ""
            except:
                model_verdict = ""

        save_feedback(url, model_verdict, user_verdict, comment)
        return jsonify({'status': 'ok', 'message': 'Спасибо за отзыв!'})
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)}), 500

@app.route('/admin/feedbacks')
def admin_feedbacks():
    try:
        df = get_all_feedbacks()
        if df.empty:
            return render_template('admin.html', feedbacks=[])

        feedbacks = []
        for _, row in df.iterrows():
            mismatch = row['model_verdict'] != row['user_verdict'] and row['user_verdict'] != 'other'
            feedbacks.append({
                'id': row['id'],
                'url': row['url'],
                'model_verdict': row['model_verdict'],
                'user_verdict': row['user_verdict'],
                'user_comment': row['user_comment'],
                'timestamp': row['timestamp'],
                'mismatch': mismatch
            })
        return render_template('admin.html', feedbacks=feedbacks)
    except Exception as e:
        return f'<h1>Ошибка</h1><p>{e}</p><a href="/">На главную</a>'

@app.route('/admin/download-db')
@app.route('/download-db')
def download_db():
    try:
        base_dir = Path(__file__).parent.parent
        db_path = base_dir / 'data' / 'feedback.db'
        print(f"[DEBUG] Ищем БД по пути: {db_path}", file=sys.stderr)

        if not db_path.exists():
            alt_paths = [Path('data/feedback.db'), Path('feedback.db')]
            for alt in alt_paths:
                if alt.exists():
                    db_path = alt
                    break
            else:
                return f"❌ Файл feedback.db не найден. Искали в: {db_path}", 404

        return send_file(db_path, as_attachment=True, download_name='feedback.db')
    except PermissionError:
        return "❌ Нет прав на чтение файла БД. Проверьте права доступа к папке data/", 403
    except Exception as e:
        print(f"[ERROR] Ошибка при скачивании БД: {e}", file=sys.stderr)
        return f"❌ Внутренняя ошибка сервера: {e}", 500

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
