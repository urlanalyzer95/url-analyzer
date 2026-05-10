import sys
import os
import re
from datetime import datetime, timedelta
from urllib.parse import urlparse
from pathlib import Path
import math
import pandas as pd
import joblib
import numpy as np
from flask import Flask, render_template, request, jsonify, send_file
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash

from ml.features import extract_features, feature_cols
from ml.explain_model import ModelExplainer

app = Flask(__name__, template_folder='templates')
auth = HTTPBasicAuth()
cache = {}

ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'default_secret_change_me')
users = {"admin": generate_password_hash(ADMIN_PASSWORD)}

@auth.verify_password
def verify_password(username, password):
    if username in users and check_password_hash(users.get(username), password):
        return username
    return None

# Подключение БД
try:
    from db import init_db, save_feedback, get_all_feedbacks, get_db_path
except ImportError:
    try:
        from app.db import init_db, save_feedback, get_all_feedbacks, get_db_path
    except ImportError:
        def init_db(): pass
        def save_feedback(*args, **kwargs): pass
        def get_all_feedbacks(): return pd.DataFrame()
        def get_db_path(): return 'data/feedback.db'

model = None
explainer = None
BASE_DIR = Path(__file__).parent

def load_model():
    global model, explainer
    try:
        base = Path(__file__).parent.parent
        model_path = base / 'ml' / 'model.pkl'
        if model_path.exists():
            model = joblib.load(model_path)
            explainer = ModelExplainer(model_path=str(model_path))
            # Тестовое предсказание
            test_feats = extract_features('https://google.com')
            prob = model.predict_proba(test_feats[feature_cols].values.reshape(1, -1))[0][1]
            print(f"[DEBUG] google.com probability: {prob:.3f}", file=sys.stderr)
            print(f"✅ Модель загружена: {model_path}", file=sys.stderr)
            return True
        else:
            print(f"⚠️ Модель не найдена: {model_path}", file=sys.stderr)
    except Exception as e:
        print(f"⚠️ Ошибка загрузки модели: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
    model = None
    explainer = None
    return False

def normalize_url(url):
    return url.strip().lower().rstrip('/')

def is_valid_url(url):
    if not url.startswith(('http://', 'https://')) or ' ' in url:
        return False
    try:
        netloc = urlparse(url).netloc.split(':')[0]
        return '.' in netloc and len(netloc) > 2
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

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/health')
def health():
    return jsonify({
        'status': 'ok',
        'model_loaded': model is not None,
        'model_version': 'v2.2_explainable'
    })

@app.route('/check', methods=['POST'])
def check_url():
    data = request.json or {}
    raw_url = data.get('url', '').strip()
    if not raw_url:
        return jsonify({'error': 'URL не указан'}), 400

    url = normalize_url(raw_url)
    if not is_valid_url(url):
        return jsonify({'error': 'Невалидный URL'}), 400

    cached = get_cached(url)
    if cached:
        return jsonify(cached)

    if explainer is None:
        # fallback: просто вероятность
        try:
            feats = extract_features(url)
            X = feats[feature_cols].values.reshape(1, -1)
            probability = model.predict_proba(X)[0][1]
        except:
            probability = 0.5
        reasons = ["ML модель определила уровень опасности на основе признаков URL"]
    else:
        explanation = explainer.predict_with_explanation(url)
        probability = explanation['probability'] / 100.0
        reasons = explanation['reasons']

    if probability >= 0.7:
        verdict, text = "dangerous", "🔴 ОПАСНО"
    elif probability >= 0.4:
        verdict, text = "suspicious", "🟡 ПОДОЗРИТЕЛЬНО"
    else:
        verdict, text = "safe", "🟢 БЕЗОПАСНО"

    result = {
        'url': raw_url,
        'verdict': verdict,
        'verdict_text': text,
        'score': round(probability * 100),
        'explanations': reasons
    }
    set_cached(url, result)
    return jsonify(result)

@app.route('/feedback', methods=['POST'])
def feedback():
    try:
        data = request.json or {}
        url = data.get('url', '').strip()
        model_verdict = data.get('model_verdict', '')
        user_verdict = data.get('user_verdict', '')
        comment = data.get('comment', '')

        if url and not is_valid_url(normalize_url(url)):
            model_verdict = ""

        save_feedback(url, model_verdict, user_verdict, comment)
        return jsonify({'status': 'ok', 'message': 'Спасибо за отзыв!'})
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)}), 500

@app.route('/admin')
@app.route('/admin/feedbacks')
@auth.login_required
def admin_feedbacks():
    try:
        df = get_all_feedbacks()
        if df.empty:
            return render_template('admin.html', paginated_feedbacks=[],
                                 current_page=1, total_pages=0, total_feedbacks=0)

        page = request.args.get('page', 1, type=int)
        per_page = 20

        all_feedbacks = []
        for _, row in df.iterrows():
            mismatch = (row['model_verdict'] != row['user_verdict'] 
                       and row['user_verdict'] not in ['', 'other'])
            all_feedbacks.append({
                'id': row['id'],
                'url': row['url'],
                'model_verdict': row['model_verdict'],
                'user_verdict': row['user_verdict'],
                'user_comment': row['user_comment'],
                'timestamp': row['timestamp'],
                'mismatch': mismatch
            })

        all_feedbacks.sort(key=lambda x: x['id'], reverse=True)
        total_feedbacks = len(all_feedbacks)
        total_pages = math.ceil(total_feedbacks / per_page) if total_feedbacks > 0 else 1
        page = max(1, min(page, total_pages))

        start_idx = (page - 1) * per_page
        paginated = all_feedbacks[start_idx:start_idx + per_page]

        return render_template('admin.html',
                             paginated_feedbacks=paginated,
                             current_page=page,
                             total_pages=total_pages,
                             total_feedbacks=total_feedbacks)
    except Exception as e:
        return f'<h1>Ошибка</h1><p>{e}</p><a href="/">На главную</a>'

@app.route('/admin/download-db')
@auth.login_required
def admin_download_db():
    return download_db()

@app.route('/download-db')
def download_db():
    try:
        db_path = Path(get_db_path())
        if not db_path.exists():
            for alt in [Path('data/feedback.db'), Path('feedback.db')]:
                if alt.exists():
                    db_path = alt
                    break
            else:
                return "❌ Файл feedback.db не найден.", 404
        return send_file(db_path, as_attachment=True, download_name='feedback.db')
    except PermissionError:
        return "❌ Нет прав на чтение файла БД.", 403
    except Exception as e:
        return f"❌ Ошибка: {e}", 500

if __name__ == '__main__':
    init_db()
    load_model()
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=False)