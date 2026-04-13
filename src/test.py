# test_db_only.py - без pandas, без всего
import sqlite3
from pathlib import Path

DB_PATH = 'data/feedback.db'

print(f"Файл существует: {Path(DB_PATH).exists()}")
print(f"Размер файла: {Path(DB_PATH).stat().st_size if Path(DB_PATH).exists() else 0} байт")

try:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Проверяем целостность
    cursor.execute("PRAGMA integrity_check")
    result = cursor.fetchone()
    print(f"Проверка целостности: {result[0]}")
    
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = cursor.fetchall()
    print(f"Таблицы: {tables}")
    
    conn.close()
    print("✅ БД работает нормально")
    
except Exception as e:
    print(f"❌ Ошибка: {e}")