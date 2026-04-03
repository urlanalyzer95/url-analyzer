"""
Модуль для работы с базой данных отзывов
"""

import sqlite3
import os
import pandas as pd

DB_PATH = 'data/feedback.db'


def init_db():
    """Создаёт таблицу для отзывов, если её нет"""
    os.makedirs('data', exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS feedbacks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT, 
            model_verdict TEXT, 
            user_verdict TEXT,
            user_comment TEXT, 
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()


def save_feedback(url, model_verdict, user_verdict, user_comment=""):
    """Сохраняет отзыв в БД"""
    conn = sqlite3.connect(DB_PATH)
    conn.execute('''
        INSERT INTO feedbacks (url, model_verdict, user_verdict, user_comment) 
        VALUES (?, ?, ?, ?)
    ''', (url, model_verdict, user_verdict, user_comment))
    conn.commit()
    conn.close()


def get_all_feedbacks():
    """Возвращает все отзывы из БД в виде DataFrame"""
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query(
        "SELECT id, url, model_verdict, user_verdict, user_comment, timestamp "
        "FROM feedbacks ORDER BY timestamp DESC",
        conn
    )
    conn.close()
    return df


def get_db_path():
    """Возвращает путь к файлу БД"""
    return DB_PATH