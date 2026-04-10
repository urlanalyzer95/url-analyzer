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

# ---- Подключение модуля работы с БД (feedback.db) ----
# Пытаемся импортировать как обычный модуль, иначе как часть пакета app.
try:
    from db import init_db, save_feedback, get_all_feedbacks, get_db_path
except ImportError:
    from app.db import init_db, save_feedback, get_all_feedbacks, get_db_path

# Функция извлечения признаков из URL (определена в ml/features.py)
from ml.features import extract_features

# Инициализация Flask-приложения и папки с шаблонами
app = Flask(__name__, template_folder='templates')

# Простой словарный кэш: ключ – нормализованный URL, значение – (результат, timestamp)
cache = {}

# ---------- Вспомогательные функции ----------
def normalize_url(url):
    """Приводит URL к стандартному виду: добавляет https:// если нужно,
    переводит в нижний регистр, убирает завершающий слэш."""
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return url.lower().rstrip('/')

def is_valid_url(url):
    """Базовая проверка корректности URL: схема http/https, наличие точки в домене."""
    if not url.startswith(('http://', 'https://')) or ' ' in url:
        return False
    try:
        netloc = urlparse(url).netloc.split(':')[0]
        return '.' in netloc
    except:
        return False

def get_cached(url):
    """Возвращает закэшированный результат проверки."""
    if url in cache:
        data, timestamp = cache[url]
        if datetime.now() - timestamp < timedelta(hours=24):
            return data
        del cache[url]
    return None

def set_cached(url, data):
    """Сохраняет результат проверки в кэш с текущим временем."""
    cache[url] = (data, datetime.now())

# Список URL, которые считаются абсолютно безопасными (только главная страница, без пути).
# Любые подстраницы этих доменов будут проверяться ML-моделью.
TRUSTED_HOMEPAGES = [
    'https://google.com',
    'https://yandex.ru',
    'https://ya.ru',         
    'https://github.com',
    'https://stackoverflow.com',
    'https://wikipedia.org',
    'https://youtube.com',
    'https://instagram.com',
    'https://facebook.com',
    'https://twitter.com',
    'https://amazon.com',
    'https://apple.com',
    'https://microsoft.com',
    'https://reddit.com',
    'https://linkedin.com'
]

def is_trusted_homepage(url):
    """Проверяет, является ли URL главной страницей доверенного сайта."""
    normalized = normalize_url(url)
    return normalized in TRUSTED_HOMEPAGES

# ---------- Загрузка ML-модели и датасета ----------
model = None
feature_columns = []          # имена признаков, используемых моделью
features_df = None            # DataFrame с признаками для поиска точных совпадений

BASE_DIR = Path(__file__).parent.parent   # корень проекта (поднимаемся из app/)

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

# Инициализация базы данных отзывов (создаётся таблица, если её нет)
init_db()

# ---------- Основная функция предсказания ----------
def predict(url):
    """
    Возвращает вероятность того, что URL является фишинговым (от 0.0 до 1.0).
    Логика:
      1. Поиск точного совпадения в датасете (если есть, берём предсказание модели).
      2. Эвристики для IP-адресов и сервисов сокращения ссылок.
      3. Иначе – извлечение признаков и предсказание ML-моделью.
      4. Для URL с подозрительными словами ограничиваем вероятность 70%,
         чтобы они не уходили в "опасно".
    """
    if model is None:
        return 0.5   # fallback, если модель не загружена

    try:
        url_lower = url.lower().rstrip('/')

        # ---- 1. Поиск в датасете (точное совпадение) ----
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

        # ---- 2. Эвристики для явно опасных шаблонов ----
        # IP-адрес вместо домена → почти всегда фишинг
        if re.search(r'\d{1,3}(\.\d{1,3}){3}', url_lower):
            return 0.95

        # Сервисы сокращения ссылок 
        shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly']
        if any(s in url_lower for s in shorteners):
            return 0.70

        # ---- 3. ML-модель для новых/неизвестных URL ----
        features = extract_features(url)
        features_df_input = pd.DataFrame([features], columns=feature_columns)
        proba = model.predict_proba(features_df_input)[0][1]

        # ---- 4. Ограничение для подозрительных слов ----
        # Если в URL есть слова login, verify, account и т.п., ограничиваем 70%,
        # чтобы такие ссылки чаще были "подозрительными", а не "опасными".
        suspicious_words = ['login', 'verify', 'account', 'secure', 'update', 'confirm', 'signin']
        if any(word in url_lower for word in suspicious_words):
            proba = min(proba, 0.70)

        return float(proba)
    except Exception as e:
        print(f"ML ошибка: {e}", file=sys.stderr)
        return 0.5

# ---------- Эндпоинты (API) ----------
@app.route('/')
def index():
    """Главная страница – форма для ввода URL."""
    return render_template('index.html')

@app.route('/health')
def health():
    """Проверка работоспособности сервера и наличия модели."""
    return jsonify({
        'status': 'ok',
        'model_loaded': model is not None,
        'model_version': 'v2.0'
    })

@app.route('/check', methods=['POST'])
def check_url():
    """
    Основной эндпоинт проверки URL.
    Принимает JSON: {"url": "..."}
    Возвращает вердикт, текст, процент опасности и объяснение.
    """
    data = request.json
    raw_url = data.get('url', '').strip()
    if not raw_url:
        return jsonify({'error': 'URL не указан'}), 400

    url = normalize_url(raw_url)
    if not is_valid_url(url):
        return jsonify({'error': 'Невалидный URL'}), 400

    # Проверяем кэш
    cached = get_cached(url)
    if cached:
        return jsonify(cached)

    # Белый список главных страниц – мгновенный ответ safe
    if is_trusted_homepage(url):
        result = {
            'url': raw_url,
            'verdict': 'safe',
            'verdict_text': '🟢 БЕЗОПАСНО',
            'score': 0,
            'explanations': ['Главная страница доверенного сайта']
        }
        set_cached(url, result)
        return jsonify(result)

    # Вычисляем вероятность опасности
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
    """
    Сохраняет отзыв пользователя о правильности проверки.
    Если URL невалидный – поле model_verdict очищается.
    """
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
                    model_verdict = ""   # невалидный URL – нет вердикта модели
            except:
                model_verdict = ""

        save_feedback(url, model_verdict, user_verdict, comment)
        return jsonify({'status': 'ok', 'message': 'Спасибо за отзыв!'})
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)}), 500

# @app.route('/admin/feedbacks')
# def admin_feedbacks():
#     """
#     Админ-панель: показывает все отзывы из БД.
#     Подсвечивает строки, где вердикт модели не совпадает с мнением пользователя.
#     """
#     try:
#         df = get_all_feedbacks()
#         if df.empty:
#             return render_template('admin.html', feedbacks=[])

#         feedbacks = []
#         for _, row in df.iterrows():
#             mismatch = row['model_verdict'] != row['user_verdict'] and row['user_verdict'] != 'other'
#             feedbacks.append({
#                 'id': row['id'],
#                 'url': row['url'],
#                 'model_verdict': row['model_verdict'],
#                 'user_verdict': row['user_verdict'],
#                 'user_comment': row['user_comment'],
#                 'timestamp': row['timestamp'],
#                 'mismatch': mismatch
#             })
#         return render_template('admin.html', feedbacks=feedbacks)
#     except Exception as e:
#         return f'<h1>Ошибка</h1><p>{e}</p><a href="/">На главную</a>'

@app.route('/admin/feedbacks')
def admin_feedbacks():
    """
    Админ-панель: показывает все отзывы из БД с пагинацией (20 на страницу).
    """
    try:
        df = get_all_feedbacks()
        if df.empty:
            return render_template('admin.html', feedbacks=[], paginated_feedbacks=[], 
                                 current_page=1, total_pages=0, total_feedbacks=0)

        # Получаем номер страницы из GET-параметра (по умолчанию 1)
        page = request.args.get('page', 1, type=int)
        per_page = 20  # 20 отзывов на страницу

        # Преобразуем DataFrame в список словарей
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

        # Сортируем по ID (новые сверху) или по timestamp
        all_feedbacks.sort(key=lambda x: x['id'], reverse=True)

        # Вычисляем пагинацию
        total_feedbacks = len(all_feedbacks)
        total_pages = ceil(total_feedbacks / per_page)

        # Корректируем номер страницы
        if page < 1:
            page = 1
        if page > total_pages and total_pages > 0:
            page = total_pages

        # Получаем отзывы для текущей страницы
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



@app.route('/admin/download-db')
@app.route('/download-db')
def download_db():
    """Скачивание файла базы данных feedback.db."""
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
