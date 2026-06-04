import pandas as pd
from pathlib import Path
import sys

sys.path.append(str(Path(__file__).parent.parent / 'ml'))
from features import extract_features, feature_cols

DATASET_FILE = 'data/processed/url_dataset_features.csv'
NEW_EXAMPLES = 'data/new_training_examples.csv'
BACKUP_FILE = 'data/processed/url_dataset_features_backup.csv'

def update_dataset():
    print(" " )
    print(" ДОБАВЛЕНИЕ НОВЫХ ОТЗЫВОВ В ДАТАСЕТ")
    print(" ")

    # 1. Проверяем новые отзывы
    if not Path(NEW_EXAMPLES).exists():
        print(" Нет новых отзывов для добавления")
        return
    new_df = pd.read_csv(NEW_EXAMPLES)
    print(f" Новых отзывов: {len(new_df)}")

    # 2. Загружаем основной датасет
    if not Path(DATASET_FILE).exists():
        print(f" Датасет не найден: {DATASET_FILE}")
        return
    current_df = pd.read_csv(DATASET_FILE)
    current_count = len(current_df)
    print(f" Текущий датасет: {current_count:,} записей")

    # Создаём бэкап перед изменениями
    Path(BACKUP_FILE).write_bytes(Path(DATASET_FILE).read_bytes())
    print(f" Создан бэкап: {BACKUP_FILE}")

    # 3. Извлекаем признаки (с защитой от сбоев)
    print("\n Извлечение признаков...")
    all_features = []
    successful = 0
    for idx, row in new_df.iterrows():
        url = row['url']
        try:
            feats_df = extract_features(url)
            if set(feats_df.columns) != set(feature_cols):
                print(f"    Пропущен {url[:40]}... (несовпадение признаков)")
                continue
            all_features.append(feats_df.iloc[0].tolist())
            successful += 1
        except Exception as e:
            print(f"    Ошибка {url[:40]}...: {e}")
    print(f"    Успешно обработано: {successful}/{len(new_df)}")

    if not all_features:
        print(" Нет валидных примеров для добавления")
        return

    # 4. Собираем новый блок
    new_features_df = pd.DataFrame(all_features, columns=feature_cols)
    # Берём URL и label только из успешно обработанных
    valid_urls = new_df.iloc[:successful]
    new_features_df['url'] = valid_urls['url'].values
    new_features_df['label'] = valid_urls['label'].values

    # 5. Объединяем и чистим
    updated_df = pd.concat([current_df, new_features_df], ignore_index=True)
    before_dedup = len(updated_df)
    updated_df = updated_df.drop_duplicates(subset=['url'], keep='last')
    after_dedup = len(updated_df)

    # 6. Сохраняем
    updated_df.to_csv(DATASET_FILE, index=False)
    print(f"\n ДАТАСЕТ ОБНОВЛЁН:")
    print(f"   Было: {current_count:,}")
    print(f"   Добавлено: {successful:,}")
    print(f"   Удалено дубликатов: {before_dedup - after_dedup}")
    print(f"   Итого: {after_dedup:,}")

    # 7. Удаляем временный файл отзывов
    Path(NEW_EXAMPLES).unlink()
    print(f"\n Удалён {NEW_EXAMPLES}")

if __name__ == '__main__':
    try:
        update_dataset()
    except Exception as e:
        print(f"\n КРИТИЧЕСКАЯ ОШИБКА: {e}")
        print(" Основной датасет не изменён. Проверь бэкап.")