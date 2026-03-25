from flask import Flask, render_template, request, jsonify
import json
import sqlite3
import os
from datetime import datetime, timedelta
import sys
import joblib

app = Flask(__name__)

# Загрузка ML-модели при старте сервера
print("📦 Загрузка ML-модели...")
sys.path.append('ml')
from features import extract_features

try:
    model = joblib.load('ml/model.pkl')
    print("✅ Модель успешно загружена")
except Exception as e:
    print(f"❌ Ошибка загрузки модели: {e}")
    model = None

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
        
        # Извлечение признаков
        features = extract_features(url)
        
        # Предсказание (вероятность класса 1 - фишинг)
        score = model.predict_proba([features])[0][1]
        
    except Exception as e:
        print(f"Ошибка при анализе URL {url}: {e}")
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
    
    # Генерация объяснений на основе признаков
    explanations = []
    try:
        features_list = extract_features(url)
        # Признаки: [длина, точки, слэши, has_ip, susp_count, is_short, has_at, has_https]
        
        if features_list[3] == 1:  # has_ip
            explanations.append("Ссылка содержит IP-адрес вместо доменного имени")
        if features_list[4] > 0:  # suspicious_words_count
            explanations.append(f"Обнаружены подозрительные слова")
        if features_list[5] == 1:  # is_shortened
            explanations.append("Использован сервис сокращения ссылок")
        if features_list[6] == 1:  # has_at
            explanations.append("Ссылка содержит символ @")
        if features_list[7] == 0:  # not https
            explanations.append("Отсутствует защищенное соединение HTTPS")
            
    except:
        # fallback объяснения
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

# Проверка здоровья сервера
@app.route('/health')
def health():
    return jsonify({
        'status': 'ok',
        'model_loaded': model is not None
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
