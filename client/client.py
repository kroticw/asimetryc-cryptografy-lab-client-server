import requests
import json
import time
import os
import random
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64

# Пути к ключам
CLIENT_PRIVATE_KEY_PATH = "client_private_key.pem"
CLIENT_PUBLIC_KEY_PATH = "client_public_key.pem"
SERVER_PUBLIC_KEY_PATH = "server_public_key.pem"

class Client:
    def __init__(self, client_id, server_ip="127.0.0.1", server_port=8080):
        self.client_id = client_id
        self.server_url = f"http://{server_ip}:{server_port}"
        self.server_public_key = None
        self.is_authenticated = False
        self.generate_keys()
        self.fetch_server_public_key()
        self.register()
    
    def generate_keys(self):
        """Генерация ключевой пары клиента, если она не существует"""
        if not os.path.exists(CLIENT_PRIVATE_KEY_PATH):
            print("Генерация ключей RSA для клиента...")
            key = RSA.generate(2048)
            
            # Сохранение приватного ключа
            with open(CLIENT_PRIVATE_KEY_PATH, "wb") as f:
                f.write(key.export_key())
            
            # Сохранение публичного ключа
            with open(CLIENT_PUBLIC_KEY_PATH, "wb") as f:
                f.write(key.publickey().export_key())
            
            print("Ключи клиента сгенерированы и сохранены")
    
    def load_private_key(self):
        """Загрузка приватного ключа клиента"""
        with open(CLIENT_PRIVATE_KEY_PATH, "rb") as f:
            return RSA.import_key(f.read())
    
    def load_public_key(self):
        """Загрузка публичного ключа клиента"""
        with open(CLIENT_PUBLIC_KEY_PATH, "rb") as f:
            return RSA.import_key(f.read())
    
    def fetch_server_public_key(self):
        """Получение публичного ключа сервера"""
        try:
            response = requests.get(f"{self.server_url}/get_server_public_key")
            if response.status_code == 200:
                server_public_key_str = response.json()["public_key"]
                self.server_public_key = RSA.import_key(server_public_key_str)
                
                # Сохранение публичного ключа сервера
                with open(SERVER_PUBLIC_KEY_PATH, "wb") as f:
                    f.write(self.server_public_key.export_key())
                
                print("Публичный ключ сервера получен и сохранен")
            else:
                print(f"Ошибка получения ключа сервера: {response.json()}")
        except Exception as e:
            print(f"Ошибка при получении публичного ключа сервера: {e}")
    
    def register(self):
        """Регистрация клиента на сервере"""
        try:
            public_key = self.load_public_key()
            
            response = requests.post(
                f"{self.server_url}/register",
                json={
                    "client_id": self.client_id,
                    "public_key": public_key.export_key().decode()
                }
            )
            
            if response.status_code == 200:
                print("Клиент успешно зарегистрирован на сервере")
            else:
                print(f"Ошибка регистрации: {response.json()}")
        except Exception as e:
            print(f"Ошибка при регистрации клиента: {e}")
    
    def authenticate_with_timestamp(self):
        """Аутентификация с использованием метки времени"""
        try:
            # Получение текущего времени
            timestamp = int(time.time())
            
            # Формирование сообщения
            message = f"{self.client_id}:{timestamp}".encode()
            
            # Хеширование сообщения
            h = SHA256.new(message)
            
            # Подписание хеша приватным ключом
            private_key = self.load_private_key()
            signature = pkcs1_15.new(private_key).sign(h)
            
            # Кодирование подписи в base64
            signature_b64 = base64.b64encode(signature).decode()
            
            # Отправка запроса на сервер
            response = requests.post(
                f"{self.server_url}/auth/timestamp",
                json={
                    "client_id": self.client_id,
                    "timestamp": timestamp,
                    "signature": signature_b64
                }
            )
            
            if response.status_code == 200:
                print("Аутентификация по метке времени успешна")
                self.is_authenticated = True
                return True
            else:
                print(f"Ошибка аутентификации: {response.json()}")
                return False
        except Exception as e:
            print(f"Ошибка при аутентификации с меткой времени: {e}")
            return False
    
    def authenticate_with_challenge(self):
        """Аутентификация с использованием случайных чисел (запрос-ответ)"""
        try:
            # Запрос случайного числа от сервера
            response = requests.post(
                f"{self.server_url}/auth/challenge",
                json={"client_id": self.client_id}
            )
            
            if response.status_code != 200:
                print(f"Ошибка при запросе nonce: {response.json()}")
                return False
            
            # Получение nonce
            nonce = response.json()["nonce"]
            print(f"Получен nonce от сервера: {nonce}")
            
            # Формирование сообщения
            message = str(nonce).encode()
            
            # Хеширование сообщения
            h = SHA256.new(message)
            
            # Подписание хеша приватным ключом
            private_key = self.load_private_key()
            signature = pkcs1_15.new(private_key).sign(h)
            
            # Кодирование подписи в base64
            signature_b64 = base64.b64encode(signature).decode()
            
            # Отправка подписанного nonce на сервер
            verify_response = requests.post(
                f"{self.server_url}/auth/challenge/verify",
                json={
                    "client_id": self.client_id,
                    "signature": signature_b64
                }
            )
            
            if verify_response.status_code == 200:
                print("Аутентификация по случайному числу успешна")
                self.is_authenticated = True
                return True
            else:
                print(f"Ошибка аутентификации: {verify_response.json()}")
                return False
        except Exception as e:
            print(f"Ошибка при аутентификации с случайным числом: {e}")
            return False
    
    def authenticate_mutual(self):
        """Взаимная аутентификация с использованием случайных чисел"""
        try:
            # Генерация случайного числа клиента
            client_nonce = random.randint(100000, 999999)
            print(f"Сгенерирован nonce клиента: {client_nonce}")
            
            # Отправка ID клиента и его nonce на сервер
            response = requests.post(
                f"{self.server_url}/auth/mutual",
                json={
                    "client_id": self.client_id,
                    "client_nonce": client_nonce
                }
            )
            
            if response.status_code != 200:
                print(f"Ошибка при инициализации взаимной аутентификации: {response.json()}")
                return False
            
            # Получение nonce сервера и его подписи
            server_nonce = response.json()["server_nonce"]
            server_signature_b64 = response.json()["signature"]
            
            print(f"Получен nonce сервера: {server_nonce}")
            
            # Проверка подписи сервера
            message = f"{self.client_id}:{client_nonce}:{server_nonce}".encode()
            h = SHA256.new(message)
            
            try:
                # Декодирование подписи из base64
                server_signature = base64.b64decode(server_signature_b64)
                
                # Проверка подписи сервера
                pkcs1_15.new(self.server_public_key).verify(h, server_signature)
                print("Подпись сервера верифицирована")
            except (ValueError, TypeError):
                print("Ошибка: неверная подпись сервера")
                return False
            
            # Формирование сообщения для ответной подписи
            message = f"{self.client_id}:{client_nonce}:{server_nonce}".encode()
            h = SHA256.new(message)
            
            # Подписание хеша приватным ключом клиента
            private_key = self.load_private_key()
            signature = pkcs1_15.new(private_key).sign(h)
            
            # Кодирование подписи в base64
            signature_b64 = base64.b64encode(signature).decode()
            
            # Отправка подписи на сервер
            verify_response = requests.post(
                f"{self.server_url}/auth/mutual/verify",
                json={
                    "client_id": self.client_id,
                    "signature": signature_b64
                }
            )
            
            if verify_response.status_code == 200:
                print("Взаимная аутентификация успешна")
                self.is_authenticated = True
                return True
            else:
                print(f"Ошибка взаимной аутентификации: {verify_response.json()}")
                return False
        except Exception as e:
            print(f"Ошибка при взаимной аутентификации: {e}")
            return False
    
    def send_message(self, message):
        """Отправка сообщения на сервер"""
        if not self.is_authenticated:
            print("Ошибка: клиент не аутентифицирован")
            return False
        
        try:
            response = requests.post(
                f"{self.server_url}/message",
                json={
                    "client_id": self.client_id,
                    "message": message
                }
            )
            
            if response.status_code == 200:
                data = response.json()
                print(f"\nОтправлено: {data['original_message']}")
                print(f"Получено (перевёрнутое): {data['reversed_message']}")
                return True
            else:
                print(f"Ошибка отправки сообщения: {response.json()}")
                return False
        except Exception as e:
            print(f"Ошибка при отправке сообщения: {e}")
            return False

def print_menu():
    print("\n=== Меню ===")
    print("1. Односторонняя аутентификация с меткой времени")
    print("2. Односторонняя аутентификация с использованием случайных чисел")
    print("3. Взаимная аутентификация с использованием случайных чисел")
    print("4. Отправить сообщение")
    print("0. Выход")
    choice = input("Выберите действие: ")
    return choice

def main():
    client_id = input("Введите ID клиента: ")
    server_ip = input("Введите IP-адрес сервера (по умолчанию 127.0.0.1): ") or "127.0.0.1"
    
    client = Client(client_id, server_ip)
    
    while True:
        choice = print_menu()
        
        if choice == "1":
            client.authenticate_with_timestamp()
        elif choice == "2":
            client.authenticate_with_challenge()
        elif choice == "3":
            client.authenticate_mutual()
        elif choice == "4":
            if not client.is_authenticated:
                print("Сначала необходимо пройти аутентификацию")
                continue
            message = input("Введите сообщение для отправки: ")
            client.send_message(message)
        elif choice == "0":
            print("Выход из программы")
            break
        else:
            print("Неверный выбор, пожалуйста, попробуйте снова")

if __name__ == "__main__":
    main() 