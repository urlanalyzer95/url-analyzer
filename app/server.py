import sys
import json
import sqlite3
import os
import re
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify
import pandas as pd
import joblib

# === ПРИНУДИТЕЛЬНЫЙ ВЫВОД ЛОГОВ ===
print("=== SERVER STARTING ===", file=sys.stderr)
sys.stderr.flush()

app = Flask(__name__)

# === ФУНКЦИЯ ПРОВЕРКИ ВАЛИДНОСТИ URL ===
def is_valid_url(url):
    """Проверяет, является ли строка валидным URL"""
    if not url:
        return False
    # Должен начинаться с http:// или https://
    if not url.startswith(('http://', 'https://')):
        return False
    # Не должен содержать пробелов
    if ' ' in url:
        return False
    # Должен содержать домен с точкой
    try:
        domain = url.split('/')[2]
        if '.' not in domain:
            return False
    except:
        return False
    return True

# === ЗАГРУЗКА ПРИЗНАКОВ И МОДЕЛИ ===
print("Loading features and model...", file=sys.stderr)
sys.stderr.flush()

try:
    # Загружаем таблицу с признаками
    features_df = pd.read_csv('data/processed/url_dataset_features.csv')
    # Определяем колонки-признаки (все кроме url и label)
    feature_columns = [col for col in features_df.columns if col not in ['url', 'label']]
    print(f"✅ Загружено {len(features_df)} записей, {len(feature_columns)} признаков", file=sys.stderr)
    
    # Загружаем модель
    model = joblib.load('ml/model.pkl')
    print("✅ Model loaded successfully", file=sys.stderr)
    
except Exception as e:
    print(f"❌ Error loading features or model: {e}", file=sys.stderr)
    features_df = None
    feature_columns = []
    model = None

sys.stderr.flush()

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
        'model_loaded': model is not None and features_df is not None
    })

@app.route('/check', methods=['POST'])
def check_url():
    data = request.json
    url = data.get('url')
    
    if not url:
        return jsonify({'error': 'URL не указан'}), 400
    
    # === ПРОВЕРКА ВАЛИДНОСТИ URL ===
    if not is_valid_url(url):
        return jsonify({
            'url': url,
            'verdict': 'invalid',
            'verdict_text': '❌ НЕВАЛИДНЫЙ URL',
            'score': 0,
            'explanations': [
                'URL должен начинаться с http:// или https://',
                'URL не должен содержать пробелов',
                'Пример правильного URL: https://google.com'
            ]
        }), 400
    
    # Проверка кэша
    cached = get_cached(url)
    if cached:
        return jsonify(cached)
    
    # Анализ через ML-модель
    try:
        if model is None or features_df is None:
            raise Exception("Модель или признаки не загружены")
        
        # Ищем URL в таблице признаков
        url_row = features_df[features_df['url'] == url]
        
        if url_row.empty:
            # Если URL нет в таблице — fallback
            print(f"⚠️ URL не найден в датасете: {url}", file=sys.stderr)
            score = 0.3
            if 'login' in url.lower() or 'verify' in url.lower():
                score = 0.8
            elif 'bit.ly' in url.lower() or 'goo.gl' in url.lower():
                score = 0.6
        else:
            # Берем признаки и предсказываем
            X = url_row[feature_columns]
            score = model.predict_proba(X)[0][1]
            print(f"✅ Предсказание для {url}: score={score:.2f}", file=sys.stderr)
        
    except Exception as e:
        print(f"⚠️ Ошибка при анализе URL {url}: {e}", file=sys.stderr)
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
    
    # Проверка HTTPS
    if not url.startswith('https'):
        explanations.append("Отсутствует защищенное соединение HTTPS")
    
    # Подозрительные слова
    if 'login' in url.lower() or 'verify' in url.lower():
        explanations.append("Обнаружены подозрительные слова (login, verify)")
    
    # Сокращатели ссылок
    if 'bit.ly' in url.lower() or 'goo.gl' in url.lower() or 'tinyurl' in url.lower():
        explanations.append("Использован сервис сокращения ссылок")
    
    # IP вместо домена
    ip_pattern = re.compile(r'https?://(\d{1,3}\.){3}\d{1,3}')
    if ip_pattern.match(url):
        explanations.append("Ссылка содержит IP-адрес вместо доменного имени")
    
    # Символ @
    if '@' in url:
        explanations.append("Ссылка содержит символ @ (может использоваться для обмана)")
    
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
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
