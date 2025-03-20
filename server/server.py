from flask import Flask, request, jsonify
import json
import time
import os
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64
import random
import socket

app = Flask(__name__)

# Пути к ключам
SERVER_PRIVATE_KEY_PATH = "server_private_key.pem"
SERVER_PUBLIC_KEY_PATH = "server_public_key.pem"

# Словарь для хранения зарегистрированных клиентов и их ключей
registered_clients = {}

# Словарь для хранения временных случайных чисел (nonce) сессий
client_nonces = {}

# Словарь для хранения аутентифицированных клиентов
authenticated_clients = set()

# Генерация ключей RSA для сервера, если они не существуют
def generate_server_keys():
    if not os.path.exists(SERVER_PRIVATE_KEY_PATH):
        print("Генерация ключей RSA для сервера...")
        key = RSA.generate(2048)
        
        # Сохранение приватного ключа
        with open(SERVER_PRIVATE_KEY_PATH, "wb") as f:
            f.write(key.export_key())
        
        # Сохранение публичного ключа
        with open(SERVER_PUBLIC_KEY_PATH, "wb") as f:
            f.write(key.publickey().export_key())
        
        print("Ключи сгенерированы и сохранены")

# Загрузка ключей сервера
def load_server_keys():
    with open(SERVER_PRIVATE_KEY_PATH, "rb") as f:
        private_key = RSA.import_key(f.read())
    
    with open(SERVER_PUBLIC_KEY_PATH, "rb") as f:
        public_key = RSA.import_key(f.read())
    
    return private_key, public_key

# Маршрут для получения публичного ключа сервера
@app.route('/get_server_public_key', methods=['GET'])
def get_server_public_key():
    _, public_key = load_server_keys()
    return jsonify({
        "public_key": public_key.export_key().decode()
    })

# Маршрут для регистрации клиента
@app.route('/register', methods=['POST'])
def register_client():
    data = request.json
    client_id = data.get('client_id')
    client_public_key = data.get('public_key')
    
    if not client_id or not client_public_key:
        return jsonify({"error": "Отсутствует ID клиента или публичный ключ"}), 400
    
    # Сохранение публичного ключа клиента
    registered_clients[client_id] = {
        "public_key": client_public_key
    }
    
    print(f"Клиент {client_id} зарегистрирован")
    return jsonify({"status": "success", "message": "Клиент зарегистрирован"})

# Модифицируем функции аутентификации, чтобы добавлять успешно аутентифицированных клиентов
def mark_client_authenticated(client_id):
    authenticated_clients.add(client_id)
    print(f"Клиент {client_id} добавлен в список аутентифицированных")

# Модифицируем все функции успешной аутентификации
@app.route('/auth/timestamp', methods=['POST'])
def auth_timestamp():
    data = request.json
    client_id = data.get('client_id')
    timestamp = data.get('timestamp')
    signature = data.get('signature')
    
    if not client_id or not timestamp or not signature:
        return jsonify({"error": "Отсутствуют необходимые данные"}), 400
    
    if client_id not in registered_clients:
        return jsonify({"error": "Клиент не зарегистрирован"}), 401
    
    # Проверка актуальности временной метки (допустимая разница 5 минут)
    current_time = int(time.time())
    if abs(current_time - int(timestamp)) > 300:
        return jsonify({"error": "Временная метка устарела"}), 401
    
    # Преобразование подписи из base64
    signature_bytes = base64.b64decode(signature)
    
    # Подготовка сообщения для проверки подписи
    message = f"{client_id}:{timestamp}".encode()
    h = SHA256.new(message)
    
    try:
        # Загрузка публичного ключа клиента
        client_public_key = RSA.import_key(registered_clients[client_id]['public_key'])
        # Проверка подписи
        pkcs1_15.new(client_public_key).verify(h, signature_bytes)
        mark_client_authenticated(client_id)
        return jsonify({"status": "success", "message": "Аутентификация успешна"})
    except (ValueError, TypeError):
        return jsonify({"error": "Неверная подпись"}), 401

# 2. Протокол односторонней аутентификации с использованием случайных чисел
@app.route('/auth/challenge', methods=['POST'])
def auth_challenge_request():
    data = request.json
    client_id = data.get('client_id')
    
    if not client_id:
        return jsonify({"error": "Отсутствует ID клиента"}), 400
    
    if client_id not in registered_clients:
        return jsonify({"error": "Клиент не зарегистрирован"}), 401
    
    # Генерация случайного числа
    nonce = random.randint(100000, 999999)
    client_nonces[client_id] = nonce
    
    return jsonify({
        "status": "success", 
        "nonce": nonce
    })

@app.route('/auth/challenge/verify', methods=['POST'])
def auth_challenge_verify():
    data = request.json
    client_id = data.get('client_id')
    signature = data.get('signature')
    
    if not client_id or not signature:
        return jsonify({"error": "Отсутствуют необходимые данные"}), 400
    
    if client_id not in registered_clients or client_id not in client_nonces:
        return jsonify({"error": "Клиент не зарегистрирован или нет активного запроса"}), 401
    
    # Преобразование подписи из base64
    signature_bytes = base64.b64decode(signature)
    
    # Подготовка сообщения для проверки подписи
    nonce = client_nonces[client_id]
    message = str(nonce).encode()
    h = SHA256.new(message)
    
    try:
        # Загрузка публичного ключа клиента
        client_public_key = RSA.import_key(registered_clients[client_id]['public_key'])
        # Проверка подписи
        pkcs1_15.new(client_public_key).verify(h, signature_bytes)
        # Удаление использованного nonce
        del client_nonces[client_id]
        mark_client_authenticated(client_id)
        return jsonify({"status": "success", "message": "Аутентификация успешна"})
    except (ValueError, TypeError):
        return jsonify({"error": "Неверная подпись"}), 401

# 3. Протокол взаимной аутентификации с использованием случайных чисел
@app.route('/auth/mutual', methods=['POST'])
def auth_mutual_init():
    data = request.json
    client_id = data.get('client_id')
    client_nonce = data.get('client_nonce')
    
    if not client_id or not client_nonce:
        return jsonify({"error": "Отсутствуют необходимые данные"}), 400
    
    if client_id not in registered_clients:
        return jsonify({"error": "Клиент не зарегистрирован"}), 401
    
    # Генерация случайного числа сервера
    server_nonce = random.randint(100000, 999999)
    
    # Подготовка сообщения для подписи
    message = f"{client_id}:{client_nonce}:{server_nonce}".encode()
    h = SHA256.new(message)
    
    # Подписание сообщения приватным ключом сервера
    private_key, _ = load_server_keys()
    signature = pkcs1_15.new(private_key).sign(h)
    signature_b64 = base64.b64encode(signature).decode()
    
    # Сохранение nonce клиента для проверки
    client_nonces[client_id] = {
        "client_nonce": client_nonce,
        "server_nonce": server_nonce
    }
    
    return jsonify({
        "status": "success",
        "server_nonce": server_nonce,
        "signature": signature_b64
    })

@app.route('/auth/mutual/verify', methods=['POST'])
def auth_mutual_verify():
    data = request.json
    client_id = data.get('client_id')
    signature = data.get('signature')
    
    if not client_id or not signature:
        return jsonify({"error": "Отсутствуют необходимые данные"}), 400
    
    if client_id not in registered_clients or client_id not in client_nonces:
        return jsonify({"error": "Клиент не зарегистрирован или нет активного запроса"}), 401
    
    # Преобразование подписи из base64
    signature_bytes = base64.b64decode(signature)
    
    # Получение nonce клиента и сервера
    nonces = client_nonces[client_id]
    client_nonce = nonces["client_nonce"]
    server_nonce = nonces["server_nonce"]
    
    # Подготовка сообщения для проверки подписи
    message = f"{client_id}:{client_nonce}:{server_nonce}".encode()
    h = SHA256.new(message)
    
    try:
        # Загрузка публичного ключа клиента
        client_public_key = RSA.import_key(registered_clients[client_id]['public_key'])
        # Проверка подписи
        pkcs1_15.new(client_public_key).verify(h, signature_bytes)
        # Удаление использованных nonce
        del client_nonces[client_id]
        mark_client_authenticated(client_id)
        return jsonify({"status": "success", "message": "Взаимная аутентификация успешна"})
    except (ValueError, TypeError):
        return jsonify({"error": "Неверная подпись"}), 401

# Новый маршрут для обработки сообщений
@app.route('/message', methods=['POST'])
def process_message():
    data = request.json
    client_id = data.get('client_id')
    message = data.get('message')
    
    if not client_id or not message:
        return jsonify({"error": "Отсутствуют необходимые данные"}), 400
    
    if client_id not in authenticated_clients:
        return jsonify({"error": "Клиент не аутентифицирован"}), 401
    
    # Переворачиваем сообщение
    reversed_message = message[::-1]
    
    return jsonify({
        "status": "success",
        "original_message": message,
        "reversed_message": reversed_message
    })

if __name__ == '__main__':
    # Генерация ключей сервера при первом запуске
    generate_server_keys()
    
    # Получение IP-адреса для информирования пользователя
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    print(f"Сервер запущен на {local_ip}:8080")
    print("Используйте этот адрес при настройке клиентов в локальной сети")
    
    # Изменение host с 127.0.0.1 на 0.0.0.0 для прослушивания всех интерфейсов
    app.run(debug=True, host='0.0.0.0', port=8080) 