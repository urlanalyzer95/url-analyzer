# ml/simple_nn.py — Простая NN для классификации фишинга
import numpy as np
import pandas as pd
import joblib
from tensorflow import keras
from tensorflow.keras import layers
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import os

class SimpleNN:
    def __init__(self, input_dim=14):
        self.input_dim = input_dim
        self.model = None
        self.scaler = StandardScaler()
        self.feature_names = [
            'url_length', 'num_dots', 'num_hyphens', 'num_slashes', 'num_params',
            'has_ip', 'has_https', 'has_login', 'has_verify', 'has_account',
            'has_admin', 'has_cp_php', 'is_shortened', 'domain_length'
        ]
    
    def build_model(self):
        """Простейшая NN: 14 → 64 → 32 → 1"""
        model = keras.Sequential([
            layers.Dense(64, activation='relu', input_shape=(self.input_dim,)),
            layers.Dropout(0.3),
            layers.Dense(32, activation='relu'),
            layers.Dropout(0.2),
            layers.Dense(1, activation='sigmoid')
        ])
        
        model.compile(
            optimizer='adam',
            loss='binary_crossentropy',
            metrics=['accuracy']
        )
        self.model = model
        return model
    
    def prepare_data(self, df):
        """Подготовка данных из датасета"""
        X = df[self.feature_names].values
        y = (df['label'] == 1).astype(int).values  # 0=легит, 1=фишинг
        
        # Нормализация
        X_scaled = self.scaler.fit_transform(X)
        return train_test_split(X_scaled, y, test_size=0.2, random_state=42)
    
    def train(self, csv_path='data/processed/url_dataset_features.csv', epochs=20):
        """Обучение на твоём датасете"""
        print("📊 Загрузка данных...")
        df = pd.read_csv(csv_path)
        print(f"✅ Данные: {len(df)} URL")
        
        X_train, X_test, y_train, y_test = self.prepare_data(df)
        
        if self.model is None:
            self.build_model()
        
        print("🚀 Обучение NN...")
        history = self.model.fit(
            X_train, y_train,
            epochs=epochs,
            batch_size=64,
            validation_data=(X_test, y_test),
            verbose=1
        )
        
        # Сохранение
        self.model.save('ml/nn_model.h5')
        joblib.dump(self.scaler, 'ml/nn_scaler.pkl')
        joblib.dump(self.feature_names, 'ml/nn_features.pkl')
        
        # Метрики
        test_loss, test_acc = self.model.evaluate(X_test, y_test, verbose=0)
        print(f"✅ Точность на тесте: {test_acc:.3f}")
        return history.history
    
    def predict(self, features):
        """Предсказание для одного URL"""
        if self.model is None:
            self.load_model()
        
        # Нормализация + предсказание
        features_scaled = self.scaler.transform([features])
        prob = self.model.predict(features_scaled, verbose=0)[0][0]
        return float(prob)
    
    def load_model(self):
        """Загрузка обученной модели"""
        try:
            self.model = keras.models.load_model('ml/nn_model.h5')
            self.scaler = joblib.load('ml/nn_scaler.pkl')
            self.feature_names = joblib.load('ml/nn_features.pkl')
            print("✅ NN загружена!")
        except:
            print("❌ Модель не найдена. Обучите: python ml/simple_nn.py")
    
    def feature_importance(self):
        """Глобальная важность признаков (градиенты)"""
        if self.model is None:
            return None
        
        # Dummy input для градиентов
        dummy_input = np.zeros((1, self.input_dim))
        dummy_input = keras.backend.constant(dummy_input)
        
        with keras.backend.get_session() as sess:
            grads = keras.backend.gradients(self.model.output, self.model.input)
            grads_val = sess.run(grads, {self.model.input: dummy_input})
        
        importance = np.mean(np.abs(grads_val[0]), axis=0)
        return dict(zip(self.feature_names, importance))

# Тест и обучение
if __name__ == "__main__":
    nn = SimpleNN()
    
    # Обучение (1 раз)
    nn.train(epochs=10)
    
    # Тест предсказания
    test_features = [80, 2, 1, 3, 2, 0, 1, 1, 0, 0, 0, 0, 0, 12]  # Пример
    prob = nn.predict(test_features)
    print(f"🎯 Вероятность фишинга: {prob:.1%}")
