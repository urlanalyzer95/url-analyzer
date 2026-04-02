import sqlite3
import pandas as pd
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, List
import sys

# Добавляем путь для импорта
sys.path.append(str(Path(__file__).parent.parent))

# Пути
BASE_DIR = Path(__file__).parent.parent
DB_PATH = BASE_DIR / 'data' / 'feedback.db'
PROCESSED_FOLDER = BASE_DIR / 'data' / 'processed'
PROCESSED_FOLDER.mkdir(parents=True, exist_ok=True)


class FeedbackSystem:
    """Упрощённая система — работает со строками"""
    
    def __init__(self, db_path: str = None):
        self.db_path = db_path or str(DB_PATH)
        self._init_db()
    
    def _init_db(self):
        """Инициализация БД — совместимая с сервером"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Основная таблица для отзывов (совместима с сервером)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS feedbacks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                model_verdict TEXT NOT NULL,
                user_verdict TEXT NOT NULL,
                user_comment TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                is_processed INTEGER DEFAULT 0
            )
        ''')
        
        # Таблица для статистики (опционально)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS feedback_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                total_checks INTEGER DEFAULT 1,
                last_checked DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
    
    # def add_feedback(
    #     self,
    #     url: str,
    #     model_verdict: str,
    #     user_verdict: str,
    #     user_comment: str = ""
    # ) -> bool:
    #     """
    #     Добавить фидбек с текстовыми вердиктами
        
    #     :param url: проверяемый URL
    #     :param model_verdict: "dangerous", "suspicious", "safe"
    #     :param user_verdict: "dangerous", "suspicious", "safe", "other"
    #     :param user_comment: комментарий пользователя
    #     """
        # try:
        #     conn = sqlite3.connect(self.db_path)
        #     cursor = conn.cursor()
            
        #     # Проверяем, существует ли уже отзыв на этот URL
        #     cursor.execute('''
        #         SELECT id FROM feedbacks 
        #         WHERE url = ? AND model_verdict = ?
        #     ''', (url, model_verdict))
            
        #     existing = cursor.fetchone()
            
        #     if existing:
        #         # Обновляем существующий
        #         cursor.execute('''
        #             UPDATE feedbacks 
        #             SET user_verdict = ?, user_comment = ?, timestamp = CURRENT_TIMESTAMP, is_processed = 0
        #             WHERE id = ?
        #         ''', (user_verdict, user_comment, existing[0]))
        #     else:
        #         # Добавляем новый
        #         cursor.execute('''
        #             INSERT INTO feedbacks (url, model_verdict, user_verdict, user_comment, is_processed)
        #             VALUES (?, ?, ?, ?, 0)
        #         ''', (url, model_verdict, user_verdict, user_comment))
            
        #     # Обновляем статистику
        #     cursor.execute('''
        #         INSERT INTO feedback_stats (url, total_checks, last_checked)
        #         VALUES (?, 1, CURRENT_TIMESTAMP)
        #         ON CONFLICT(url) DO UPDATE SET
        #             total_checks = total_checks + 1,
        #             last_checked = CURRENT_TIMESTAMP
        #     ''', (url,))
            
        #     conn.commit()
        #     conn.close()
        #     return True
            
        # except Exception as e:
        #     print(f"❌ Ошибка при добавлении фидбека: {e}")
        #     return False
    
    
    # def add_feedback(self, url, model_verdict, user_verdict, user_comment=""):
    #     try:
    #         print(f"🔍 add_feedback: url={url}, model={model_verdict}, user={user_verdict}", file=sys.stderr)
        
    #         conn = sqlite3.connect(self.db_path)
    #         cursor = conn.cursor()
            
    #         # Проверяем существование таблицы
    #         cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='feedbacks'")
    #         if not cursor.fetchone():
    #             print("❌ Таблица feedbacks не существует! Создаём...", file=sys.stderr)
    #             cursor.execute('''
    #                 CREATE TABLE IF NOT EXISTS feedbacks (
    #                     id INTEGER PRIMARY KEY AUTOINCREMENT,
    #                     url TEXT NOT NULL,
    #                     model_verdict TEXT NOT NULL,
    #                     user_verdict TEXT NOT NULL,
    #                     user_comment TEXT,
    #                     timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    #                     is_processed INTEGER DEFAULT 0
    #                 )
    #             ''')
    #             conn.commit()
            
        #     # Пробуем вставить
        #     cursor.execute('''
        #         INSERT INTO feedbacks (url, model_verdict, user_verdict, user_comment, is_processed)
        #         VALUES (?, ?, ?, ?, 0)
        #     ''', (url, model_verdict, user_verdict, user_comment))
            
        #     conn.commit()
        #     print(f"✅ INSERT выполнен, lastrowid={cursor.lastrowid}", file=sys.stderr)
        #     conn.close()
        #     return True
            
        # except Exception as e:
        #     print(f"❌ Ошибка в add_feedback: {e}", file=sys.stderr)
        #     import traceback
        #     traceback.print_exc(file=sys.stderr)
        #     return False
    
    
    
    def add_feedback(self, url, model_verdict, user_verdict, user_comment=""):
    # """Добавить фидбек"""
        try:
            print(f"📝 add_feedback: {url[:50]}, model={model_verdict}, user={user_verdict}", file=sys.stderr)
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Проверяем, существует ли таблица
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='feedbacks'")
            if not cursor.fetchone():
                print("⚠️ Таблица не найдена, создаём...", file=sys.stderr)
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS feedbacks (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        url TEXT NOT NULL,
                        model_verdict TEXT NOT NULL,
                        user_verdict TEXT NOT NULL,
                        user_comment TEXT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        is_processed INTEGER DEFAULT 0
                    )
                ''')
                conn.commit()
            
            # Вставляем данные (упрощённая версия, без проверки на дубликаты)
            cursor.execute('''
                INSERT INTO feedbacks (url, model_verdict, user_verdict, user_comment, is_processed)
                VALUES (?, ?, ?, ?, 0)
            ''', (url, model_verdict, user_verdict, user_comment))
            
            conn.commit()
            print(f"✅ Отзыв добавлен, ID: {cursor.lastrowid}", file=sys.stderr)
            conn.close()
            return True
            
        except Exception as e:
            print(f"❌ Ошибка в add_feedback: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc(file=sys.stderr)
            return False
    
    
    
    def get_misclassified(self, limit: int = 100) -> pd.DataFrame:
        """Получить расхождения между моделью и пользователем"""
        conn = sqlite3.connect(self.db_path)
        
        df = pd.read_sql_query('''
            SELECT id, url, model_verdict, user_verdict, user_comment, timestamp
            FROM feedbacks
            WHERE model_verdict != user_verdict 
            AND user_verdict != 'other'
            AND is_processed = 0
            ORDER BY timestamp DESC
            LIMIT ?
        ''', conn, params=(limit,))
        
        conn.close()
        return df
    
    def get_new_examples(self, min_confirmations: int = 1) -> pd.DataFrame:
        """
        Получить новые примеры для дообучения
        
        :param min_confirmations: минимальное количество подтверждений
        """
        conn = sqlite3.connect(self.db_path)
        
        # Получаем только определённые случаи
        df = pd.read_sql_query('''
            SELECT DISTINCT url, user_verdict
            FROM feedbacks
            WHERE user_verdict IN ('dangerous', 'safe')
            AND is_processed = 0
            ORDER BY timestamp DESC
        ''', conn)
        
        conn.close()
        
        if df.empty:
            return pd.DataFrame(columns=['url', 'label'])
        
        # Конвертируем вердикты в числа для ML
        df['label'] = df['user_verdict'].map({
            'dangerous': 1,
            'safe': 0
        })
        
        # Убираем строки с неопределёнными метками
        df = df.dropna(subset=['label'])
        df['label'] = df['label'].astype(int)
        
        return df[['url', 'label']]
    
    def export_for_retraining(self, output_path: str = None) -> Optional[pd.DataFrame]:
        """
        Экспорт для дообучения
        Конвертируем строки в числа для ML
        """
        if output_path is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_path = PROCESSED_FOLDER / f'retraining_data_{timestamp}.csv'
        else:
            output_path = Path(output_path)
        
        # Получаем новые примеры
        df = self.get_new_examples()
        
        if df.empty:
            print("ℹ️ Нет данных для экспорта")
            return None
        
        # Сохраняем
        df.to_csv(output_path, index=False)
        print(f"✅ Экспортировано {len(df)} примеров в {output_path}")
        
        # Отмечаем как обработанные
        self.mark_as_processed(df['url'].tolist())
        
        return df
    
    def mark_as_processed(self, urls: List[str]) -> int:
        """Отметить URL как обработанные"""
        if not urls:
            return 0
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        placeholders = ','.join(['?'] * len(urls))
        cursor.execute(f'''
            UPDATE feedbacks 
            SET is_processed = 1 
            WHERE url IN ({placeholders})
        ''', urls)
        
        affected = cursor.rowcount
        conn.commit()
        conn.close()
        
        print(f"📝 Отмечено как обработанные: {affected} записей")
        return affected
    
    def get_stats(self) -> Dict:
        """Получить статистику"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Общее количество отзывов
        cursor.execute('SELECT COUNT(*) FROM feedbacks')
        total = cursor.fetchone()[0]
        
        # Количество расхождений
        cursor.execute('''
            SELECT COUNT(*) FROM feedbacks 
            WHERE model_verdict != user_verdict 
            AND user_verdict != 'other'
        ''')
        mismatches = cursor.fetchone()[0]
        
        # Количество непрочитанных отзывов
        cursor.execute('SELECT COUNT(*) FROM feedbacks WHERE is_processed = 0')
        unprocessed = cursor.fetchone()[0]
        
        # Распределение по вердиктам
        cursor.execute('''
            SELECT user_verdict, COUNT(*) 
            FROM feedbacks 
            GROUP BY user_verdict
        ''')
        verdict_dist = dict(cursor.fetchall())
        
        conn.close()
        
        return {
            'total_feedback': total,
            'mismatches': mismatches,
            'unprocessed': unprocessed,
            'agreements': total - mismatches,
            'verdict_distribution': verdict_dist,
            'accuracy_estimate': round((1 - mismatches/total)*100, 2) if total > 0 else None
        }
    
    def get_all_feedback(self, limit: int = 1000) -> pd.DataFrame:
        """Получить все отзывы"""
        conn = sqlite3.connect(self.db_path)
        
        df = pd.read_sql_query('''
            SELECT id, url, model_verdict, user_verdict, user_comment, 
                   timestamp, is_processed
            FROM feedbacks
            ORDER BY timestamp DESC
            LIMIT ?
        ''', conn, params=(limit,))
        
        conn.close()
        return df


# Тест
if __name__ == '__main__':
    print("🧪 Тестирование системы обратной связи...")
    
    fb = FeedbackSystem()
    
    # Тест со строками
    fb.add_feedback(
        url="https://example.com",
        model_verdict="safe",
        user_verdict="dangerous",
        user_comment="Это фишинг!"
    )
    
    print("\n📊 Статистика:", fb.get_stats())
    
    print("\n❌ Ошибки:")
    print(fb.get_misclassified())
    
    print("\n📝 Новые примеры для обучения:")
    print(fb.get_new_examples())
    
    print("\n✅ Тест завершён!")