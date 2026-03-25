#import sys
#sys.path.append('../ml')

#from features import extract_features
#import joblib

#model = joblib.load('../ml/model.pkl')



from flask import Flask, render_template, request, jsonify
import json
import sqlite3
import os
from datetime import datetime, timedelta

app = Flask(__name__)

# Простой кэш в памяти (вместо Redis)
cache = {}

def get_cached(url):
    """Получить данные из кэша"""
    if url in cache:
        data, timestamp = cache[url]
        if datetime.now() - timestamp < timedelta(hours=1):
            return data
        else:
            del cache[url]
    return None

def set_cached(url, data):
    """Сохранить данные в кэш"""
    cache[url] = (data, datetime.now())

# Главная страница
@app.route('/')
def index():
    return render_template('index.html')

# Проверка URL
@app.route('/check', methods=['POST'])
def check_url():
    data = request.json
    url = data.get('url')
    
    # Проверка кэша (вместо Redis)
    cached = get_cached(url)
    if cached:
        return jsonify(cached)
    
    # Простой анализ - нужно заменить на:
    #features = extract_features(url)
    #score = model.predict_proba([features])[0][1]   
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
    
    # Сохранение в кэш
    set_cached(url, result)
    
    return jsonify(result)

# Обратная связь
@app.route('/feedback', methods=['POST'])
def feedback():
    data = request.json
    
    # Создаём папку data, если её нет
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
    app.run(host='0.0.0.0', port=5000, debug=True)
