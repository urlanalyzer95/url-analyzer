import sys
import os
import re
from datetime import datetime, timedelta
from urllib.parse import urlparse
from flask import Flask, render_template, request, jsonify, send_file
import pandas as pd
import joblib
from pathlib import Path

# Импортируем модуль работы с БД
from app.db import init_db, save_feedback, get_all_feedbacks, get_db_path

# ИНИЦИАЛИЗАЦИЯ 
app = Flask(__name__)
cache = {}

# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ 
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
        if datetime.now() - timestamp < timedelta(hours=1):
            return data
        del cache[url]
    return None

def set_cached(url, data):
    cache[url] = (data, datetime.now())

# ЗАГРУЗКА МОДЕЛИ 
model = None
feature_columns = []
features_df = None

try:
    model_path = Path(__file__).parent.parent / 'ml' / 'model_rf_v2.pkl'
    if model_path.exists():
        model = joblib.load(model_path)
        print("✅ Модель загружена", file=sys.stderr)
    
    dataset_path = Path(__file__).parent.parent / 'data' / 'processed' / 'url_dataset_features_v2.csv'
    if dataset_path.exists():
        features_df = pd.read_csv(dataset_path)
        feature_columns = [c for c in features_df.columns if c not in ['url', 'label']]
        print(f"✅ Датасет: {len(features_df)} записей", file=sys.stderr)
except Exception as e:
    print(f"⚠️ Ошибка: {e}", file=sys.stderr)

# ПРЕДСКАЗАНИЕ (ТОЛЬКО МОДЕЛЬ) 
def predict(url):
    url_lower = url.lower().rstrip('/')
    
    if model is not None and features_df is not None:
        try:
            if 'url_norm' not in features_df.columns:
                features_df['url_norm'] = features_df['url'].apply(lambda x: x.lower().rstrip('/'))
            row = features_df[features_df['url_norm'] == url_lower]
            if not row.empty:
                X = row[feature_columns]
                return float(model.predict_proba(X)[0][1])
        except Exception as e:
            print(f"ML ошибка: {e}", file=sys.stderr)
    
    return 0.5

# ЭНДПОИНТЫ 
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
    
    score = predict(url)
    
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
        'explanations': ["ML модель определила уровень опасности"]
    }
    
    set_cached(url, result)
    return jsonify(result)

# @app.route('/feedback', methods=['POST'])
# def feedback():
#     try:
#         data = request.json
#         os.makedirs('data', exist_ok=True)
#         conn = sqlite3.connect('data/feedback.db')
#         conn.execute('''
#             CREATE TABLE IF NOT EXISTS feedbacks (
#                 id INTEGER PRIMARY KEY AUTOINCREMENT,
#                 url TEXT, model_verdict TEXT, user_verdict TEXT,
#                 user_comment TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
#             )
#         ''')
#         conn.execute('INSERT INTO feedbacks (url, model_verdict, user_verdict, user_comment) VALUES (?, ?, ?, ?)',
#                      (data.get('url'), data.get('model_verdict'), data.get('user_verdict'), data.get('comment', '')))
#         conn.commit()
#         conn.close()
#         return jsonify({'status': 'ok', 'message': 'Спасибо за отзыв!'})
#     except Exception as e:
#         return jsonify({'status': 'error', 'error': str(e)}), 500


@app.route('/feedback', methods=['POST'])
def feedback():
    try:
        data = request.json
        save_feedback(
            data.get('url'),
            data.get('model_verdict'),
            data.get('user_verdict'),
            data.get('comment', '')
        )
        return jsonify({'status': 'ok', 'message': 'Спасибо за отзыв!'})
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)}), 500

@app.route('/admin/feedbacks')
def admin_feedbacks():
    try:
        df = get_all_feedbacks()
         
        # conn = sqlite3.connect('data/feedback.db')
        # df = pd.read_sql_query("SELECT id, url, model_verdict, user_verdict, user_comment, timestamp FROM feedbacks ORDER BY timestamp DESC", conn)
        # conn.close()
        
        if df.empty:
            return '<h1>📋 Отзывы</h1><p>Пока нет</p><a href="/">На главную</a>'
        
        html = '<h1>📋 Отзывы</h1><a href="/">← На главную</a><br><br>'
        html += '<table border="1" cellpadding="5">'
        html += '<tr><th>ID</th><th>URL</th><th>Модель</th><th>Пользователь</th><th>Комментарий</th><th>Дата</th></tr>'
        
        for _, row in df.iterrows():
            mismatch = row['model_verdict'] != row['user_verdict'] and row['user_verdict'] != 'other'
            style = 'style="background-color:#ffebee;"' if mismatch else ''
            html += f'<tr {style}>'
            html += f'<td>{row["id"]}</td>'
            html += f'<td style="max-width:400px; word-break:break-all;">{row["url"][:80]}</td>'
            html += f'<td>{row["model_verdict"]}</td>'
            html += f'<td style="font-weight:bold;">{row["user_verdict"]}</td>'
            html += f'<td>{row["user_comment"][:50] if row["user_comment"] else "-"}</td>'
            html += f'<td>{row["timestamp"][:16] if row["timestamp"] else "-"}</td>'
            html += '</tr>'
        
        html += '</table><p><a href="/download-db">📥 Скачать БД с отзывами</a></p>'
        return html
    except Exception as e:
        return f'<h1>Ошибка</h1><p>{e}</p>'

@app.route('/download-db')
def download_db():
    """Скачать БД с отзывами"""
    db_path = get_db_path()
    # db_path = '/app/data/feedback.db'
    
    if os.path.exists(db_path):
        return send_file(db_path, as_attachment=True, download_name='feedback.db')
    
    if os.path.exists('data/feedback.db'):
        return send_file('data/feedback.db', as_attachment=True, download_name='feedback.db')
    
    return "❌ БД не найдена", 404

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
