import sys
import os
import re
from datetime import datetime, timedelta
from urllib.parse import urlparse
from pathlib import Path
import math

import pandas as pd
import joblib
from flask import Flask, render_template, request, jsonify, send_file
try:
    from db import init_db, save_feedback, get_all_feedbacks, get_db_path
except ImportError:
    from app.db import init_db, save_feedback, get_all_feedbacks, get_db_path

from ml.features import extract_features

app = Flask(__name__, template_folder='templates')

cache = {}

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

# --- Загрузка ML-модели и датасета ---
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

init_db()

# --- Функция предсказания (без эвристик) ---
def predict(url):
    """
    Возвращает вероятность фишинга (0.0..1.0) на основе ML-модели.
    """
    if model is None:
        return 0.5

    try:
        url_lower = url.lower().rstrip('/')

        # 1. Точное совпадение в датасете (если есть)
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

        # 2. Извлечение признаков и предсказание
        features = extract_features(url)
        features_df_input = pd.DataFrame([features], columns=feature_columns)
        proba = model.predict_proba(features_df_input)[0][1]
        return float(proba)
    except Exception as e:
        print(f"ML ошибка: {e}", file=sys.stderr)
        return 0.5

# --- Эндпоинты ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/health')
def health():
    return jsonify({
        'status': 'ok',
        'model_loaded': model is not None,
        'model_version': 'v2.0_no_heuristics'
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
            return render_template('admin.html', feedbacks=[], paginated_feedbacks=[], 
                                 current_page=1, total_pages=0, total_feedbacks=0)

        page = request.args.get('page', 1, type=int)
        per_page = 20

        all_feedbacks = []
        for _, row in df.iterrows():
            mismatch = row['model_verdict'] != row['user_verdict'] and row['user_verdict'] != 'other'
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
        total_pages = math.ceil(total_feedbacks / per_page)

        if page < 1:
            page = 1
        if page > total_pages and total_pages > 0:
            page = total_pages

        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        paginated_feedbacks = all_feedbacks[start_idx:end_idx]

        return render_template('admin.html', 
                             paginated_feedbacks=paginated_feedbacks,
                             current_page=page,
                             total_pages=total_pages,
                             total_feedbacks=total_feedbacks)
    except Exception as e:
        return f'<h1>Ошибка</h1><p>{e}</p><a href="/">На главную</a>'

@app.route('/download/db')
def download_db_redirect():
    return download_db()

@app.route('/download-db')
def download_db():
    try:
        base_dir = Path(__file__).parent.parent
        db_path = base_dir / 'data' / 'feedback.db'
        if not db_path.exists():
            alt_paths = [Path('data/feedback.db'), Path('feedback.db')]
            for alt in alt_paths:
                if alt.exists():
                    db_path = alt
                    break
            else:
                return f"❌ Файл feedback.db не найден.", 404
        return send_file(db_path, as_attachment=True, download_name='feedback.db')
    except PermissionError:
        return "❌ Нет прав на чтение файла БД.", 403
    except Exception as e:
        return f"❌ Внутренняя ошибка сервера: {e}", 500

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
