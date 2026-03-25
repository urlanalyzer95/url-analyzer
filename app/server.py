import sys
import json
import sqlite3
import os
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify

# === ПРИНУДИТЕЛЬНЫЙ ВЫВОД ЛОГОВ (сразу покажет, что скрипт запустился) ===
print("=== SERVER STARTING ===", file=sys.stderr)
sys.stderr.flush()

app = Flask(__name__)

# === ЗАГРУЗКА МОДЕЛИ ===
print("Loading model...", file=sys.stderr)
sys.stderr.flush()

import joblib
import sys
sys.path.append('ml')
from features import extract_features

try:
    model = joblib.load('ml/model.pkl')
    print("✅ Model loaded successfully", file=sys.stderr)
    sys.stderr.flush()
except Exception as e:
    print(f"❌ Model loading failed: {e}", file=sys.stderr)
    sys.stderr.flush()
    model = None

# === КЭШ В ПАМЯТИ ===
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

# === РОУТЫ ===
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/health')
def health():
    return jsonify({
        'status': 'ok',
        'model_loaded': model is not None
    })

@app.route('/check', methods=['POST'])
def check_url():
    data = request.json
    url = data.get('url')
    
    if not url:
        return jsonify({'error': 'URL не указан'}), 400
    
    # Проверка кэша
    cached = get_cached(url)
    if cached:
        return jsonify(cached)
    
    # Анализ через ML-модель
    try:
        if model is None:
            raise Exception("Модель не загружена")
        
        features = extract_features(url)
        score = model.predict_proba([features])[0][1]
        
    except Exception as e:
        print(f"⚠️ Ошибка при анализе URL {url}: {e}", file=sys.stderr)
        # fallback на простые правила
        score = 0.3
        if 'login' in url.lower() or 'verify' in url.lower():
            score = 0.8
        elif 'bit.ly' in url.lower() or 'goo.gl' in url.lower():
            score = 0.6
    
    # Вердикт
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
    try:
        features_list = extract_features(url)
        if features_list[3] == 1:
            explanations.append("Ссылка содержит IP-адрес вместо доменного имени")
        if features_list[4] > 0:
            explanations.append("Обнаружены подозрительные слова")
        if features_list[5] == 1:
            explanations.append("Использован сервис сокращения ссылок")
        if features_list[6] == 1:
            explanations.append("Ссылка содержит символ @")
        if features_list[7] == 0:
            explanations.append("Отсутствует защищенное соединение HTTPS")
    except:
        if 'login' in url.lower():
            explanations.append("Обнаружено подозрительное слово 'login'")
        if 'verify' in url.lower():
            explanations.append("Обнаружено подозрительное слово 'verify'")
        if 'bit.ly' in url.lower():
            explanations.append("Использован сервис сокращения ссылок bit.ly")
    
    if not explanations:
        explanations.append("Явных признаков фишинга не обнаружено")
    
    result = {
        'url': url,
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

if __name__ == '__main__':
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
