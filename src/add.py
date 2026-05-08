
import pandas as pd
import re
from urllib.parse import urlparse
from pathlib import Path

# ===== ВСТРОЕННАЯ ФУНКЦИЯ ИЗВЛЕЧЕНИЯ ПРИЗНАКОВ =====
def extract_features_simple(url):
    """Извлекает 14 признаков из URL — копия логики из clean_data.py"""
    url_str = str(url).lower().strip()
    
    features = {}
    
    # БАЗОВЫЕ
    features['url_length'] = len(url_str)
    features['num_dots'] = url_str.count('.')
    features['num_hyphens'] = url_str.count('-')
    features['num_slashes'] = url_str.count('/')
    features['num_params'] = len(re.findall(r'[?&]', url_str))
    
    # БЕЗОПАСНОСТЬ
    features['has_ip'] = 1 if re.search(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', url_str) else 0
    features['has_https'] = 1 if url_str.startswith('https') else 0  # Как в clean_data.py!
    
    # ПОДОЗРИТЕЛЬНЫЕ СЛОВА
    for word in ['login', 'verify', 'account', 'cp.php', 'admin']:
        features[f'has_{word}'] = 1 if word in url_str else 0
    
    # СОКРАЩАТЕЛИ
    features['is_shortened'] = 1 if any(s in url_str for s in ['bit.ly', 'goo.gl', 'tinyurl']) else 0
    
    # ДОМЕН
    try:
        features['domain_length'] = len(urlparse(url_str).netloc)
    except:
        features['domain_length'] = len(url_str)
    
    return features

# Твои списки
simple_safe = ['https://google.com',
    'https://www.google.com',
    'https://yandex.ru',
    'https://www.yandex.ru',
    'https://github.com',
    'https://www.github.com',
    'https://facebook.com',
    'https://www.facebook.com',
    'https://vk.com',
    'https://www.vk.com',
    'https://youtube.com',
    'https://www.youtube.com',
    'https://twitter.com',
    'https://www.twitter.com',
    'https://instagram.com',
    'https://www.instagram.com',]  # вставь списки выше
complex_safe = [ # Google с логинами и аккаунтами
    'https://accounts.google.com/login',
    'https://accounts.google.com/signin',
    'https://mail.google.com/mail/u/0/',
    'https://drive.google.com/file/d/123abc/view',
    'https://docs.google.com/document/d/xyz/edit',
    'https://calendar.google.com/calendar/r',
    'https://photos.google.com/album/123',
    'https://play.google.com/store/apps/details',
    'https://support.google.com/account/answer/123',
    'https://myaccount.google.com/security',
    
    # Яндекс с логинами
    'https://passport.yandex.ru/login',
    'https://mail.yandex.ru/',
    'https://disk.yandex.ru/client/disk',
    'https://music.yandex.ru/home',
    
    # GitHub
    'https://github.com/login',
    'https://github.com/settings/profile',
    'https://github.com/marketplace',
    
    # Facebook
    'https://www.facebook.com/login',
    'https://www.facebook.com/settings',
    'https://www.facebook.com/ad_campaign',
    
    # Другие
    'https://www.paypal.com/myaccount/login',
    'https://www.amazon.com/ap/signin',
    'https://outlook.live.com/mail/0/',
    'https://www.linkedin.com/login',]
simple_dangerous = ['http://185.130.5.253/login',
    'http://bit.ly/xxx',
    'http://goo.gl/malware',
    'http://tinyurl.com/phish',
    'http://192.168.1.100/verify',
    'http://10.0.0.1/login',]
complex_dangerous = [# Фишинг под Google
    'https://accounts-google-verify.com/login',
    'https://google-security-check.xyz/verify',
    'https://mail.google-account-support.com/signin',
    'https://drive-google-share.tk/file',
    'https://google-verify-account.ru/login.php',
    'https://accounts.google-security-alert.com/verify',
    'https://google-support-team.net/account/restore',
    'https://mail.google-login-secure.xyz/signin',
    
    # Фишинг под Яндекс
    'https://yandex-passport-verify.com/login',
    'https://mail.yandex-security.ru/verify',
    'https://yandex-account-restore.tk/login',
    
    # Фишинг под другие бренды
    'https://paypal-secure-verify.com/account/login',
    'https://facebook-security-check.xyz/verify',
    'https://apple-id-locked.com/unlock',
    'https://microsoft-account-verify.net/login',
    'https://amazon-order-problem.com/verify-account',
    
    # Сокращатели + фишинг
    'https://bit.ly/google-verify-now',
    'https://tinyurl.com/confirm-paypal',
    'https://goo.gl/facebook-security',]

# ===== ОСНОВНОЙ КОД =====
print("=" * 60)
print("➕ ДОБАВЛЕНИЕ НОВЫХ URL В ДАТАСЕТ")
print("=" * 60)

# Пути
DATASET_PATH = Path('data/processed/url_dataset_features.csv')

# Загружаем существующий датасет
print(f"\n📥 Загрузка: {DATASET_PATH}")
if not DATASET_PATH.exists():
    print(f"❌ Файл не найден!")
    exit(1)

df = pd.read_csv(DATASET_PATH)
print(f"✅ Загружено: {len(df):,} записей")

# Собираем все новые URL
new_urls = []
for url_list, label, desc in [
    (simple_safe, 0, "простые безопасные"),
    (complex_safe, 0, "сложные безопасные"),
    (simple_dangerous, 1, "простые опасные"),
    (complex_dangerous, 1, "сложные опасные"),
]:
    for url in url_list:
        new_urls.append({'url': url, 'label': label, 'desc': desc})

print(f"\n🔄 Добавляем {len(new_urls)} новых URL...")

# Извлекаем признаки и создаём новые строки
new_rows = []
for item in new_urls:
    url = item['url']
    label = item['label']
        # Извлекаем признаки встроенной функцией
    features = extract_features_simple(url)
    features['url'] = url
    features['label'] = label
    new_rows.append(features)

# Создаём DataFrame с новыми данными
new_df = pd.DataFrame(new_rows)

# Добавляем в основной датасет
df = pd.concat([df, new_df], ignore_index=True)

# Удаляем дубликаты по URL
before = len(df)
df = df.drop_duplicates(subset=['url'], keep='last')
after = len(df)
print(f"🗑️ Удалено дубликатов: {before - after}")

# Сохраняем
df.to_csv(DATASET_PATH, index=False)
print(f"\n💾 Сохранено: {DATASET_PATH}")
print(f"📊 Итого записей: {len(df):,}")

# Проверяем баланс
print(f"\n📈 Баланс классов:")
print(f"   🟢 Безопасных (0): {(df['label'] == 0).sum():,} ({(df['label'] == 0).mean()*100:.1f}%)")
print(f"   🔴 Опасных (1): {(df['label'] == 1).sum():,} ({(df['label'] == 1).mean()*100:.1f}%)")

print(f"\n✅ ГОТОВО! Теперь можно переобучить модель.")