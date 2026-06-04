import sys
import os
from datetime import datetime, timedelta
from urllib.parse import urlparse
from pathlib import Path
import math
import pandas as pd
import joblib
from flask import Flask, render_template, request, jsonify, send_file
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash

# FIX: Добавляем пути для импортов 
project_root = Path(__file__).parent.parent
app_dir = Path(__file__).parent
for p in [str(project_root), str(app_dir)]:
    if p not in sys.path:
        sys.path.insert(0, p)

from ml.explain_model import ModelExplainer
from ml.features import extract_features, feature_cols
from db import init_db, save_feedback, get_all_feedbacks, get_db_path

auth = HTTPBasicAuth()
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'default_secret_change_me')
users = {"admin": generate_password_hash(ADMIN_PASSWORD)}

@auth.verify_password
def verify_password(username, password):
    if username in users and check_password_hash(users.get(username), password):
        return username
    return None

app = Flask(__name__, template_folder='templates')
cache = {}
model = None
#scaler = None
explainer = None
BASE_DIR = Path(__file__).parent.parent

try:
    model_path = BASE_DIR / 'ml' / 'model.pkl'
    #scaler_path = BASE_DIR / 'ml' / 'scaler.pkl'
    if model_path.exists():
        model = joblib.load(model_path)
        #if scaler_path.exists():
            #scaler = joblib.load(scaler_path)
        explainer = ModelExplainer()
        print(f"✅ Model loaded from {model_path}", file=sys.stderr)
    else:
        print("⚠️ Model not found, running in fallback mode", file=sys.stderr)
except Exception as e:
    print(f"⚠️ Error loading model: {e}", file=sys.stderr)
    model = None

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
    except Exception:
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

def predict(url):
    if model is None:
        return 0.5
    try:
        feats = extract_features(url)
        X = feats.values.reshape(1, -1)
        #if scaler is not None:
            #X = scaler.transform(X)
        proba = model.predict_proba(X)[0][1]
        return float(proba)
    except Exception as e:
        print(f"ML error: {e}", file=sys.stderr)
        return 0.5

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/health')
def health():
    return jsonify({
        'status': 'ok',
        'model_loaded': model is not None,
        'model_version': 'v3.6_render_fixed'
    })

@app.route('/check', methods=['POST'])
def check_url():
    data = request.json
    raw_url = data.get('url', '').strip()
    if not raw_url:
        return jsonify({'error': 'URL not specified'}), 400
    url = normalize_url(raw_url)
    if not is_valid_url(url):
        return jsonify({'error': 'Invalid URL'}), 400

    cached = get_cached(url)
    if cached:
        return jsonify(cached)

    probability = predict(url)

    if probability >= 0.8:
        verdict, text = "dangerous", "🔴 ОПАСНО"
    elif probability >= 0.6:
        verdict, text = "suspicious", "🟡 ПОДОЗРИТЕЛЬНО"
    else:
        verdict, text = "safe", "🟢 БЕЗОПАСНО"

    explanations = []
    if explainer is not None:
        try:
            expl_data = explainer.predict_with_explanation(url)
            explanations = expl_data.get('reasons', [])
        except Exception:
            explanations = ["ML model determined threat level"]
    else:
        explanations = ["Model not loaded"]

    result = {
        'url': raw_url,
        'verdict': verdict,
        'verdict_text': text,
        'score': round(probability * 100),
        'explanations': explanations
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
            except Exception:
                model_verdict = ""
        save_feedback(url, model_verdict, user_verdict, comment)
        return jsonify({'status': 'ok', 'message': 'Feedback saved'})
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)}), 500

@app.route('/admin')
@app.route('/admin/feedbacks')
@auth.login_required
def admin_feedbacks():
    try:
        df = get_all_feedbacks()
        # if df.empty:
        #     return render_template('admin.html', paginated_feedbacks=[], current_page=1, total_pages=0, total_feedbacks=0)
        # page = request.args.get('page', 1, type=int)
        # per_page = 20
        
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
        
        # total_feedbacks = len(all_feedbacks)
        # total_pages = math.ceil(total_feedbacks / per_page) if total_feedbacks > 0 else 1
        # if page < 1:
        #     page = 1
        # if page > total_pages:
        #     page = total_pages
        # start_idx = (page - 1) * per_page
        # end_idx = start_idx + per_page
        # paginated_feedbacks = all_feedbacks[start_idx:end_idx]
        # return render_template('admin.html',
        #                        paginated_feedbacks=paginated_feedbacks,
        #                        current_page=page,
        #                        total_pages=total_pages,
        #                        total_feedbacks=total_feedbacks)

        return render_template('admin.html', feedbacks=all_feedbacks)
    except Exception as e:
        return f'<h1>Error</h1><p>{e}</p><a href="/">Home</a>'

@app.route('/admin/download-db')
@auth.login_required
def admin_download_db():
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
                return "feedback.db not found.", 404
        return send_file(db_path, as_attachment=True, download_name='feedback.db')
    except PermissionError:
        return "Permission denied.", 403
    except Exception as e:
        return f"Internal error: {e}", 500

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
