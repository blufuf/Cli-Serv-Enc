import socket
import threading
import configparser
import os
import random
import binascii
import datetime

LOG_FILE = "chat_log.txt"

def log_message(message):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a", encoding="utf-8") as log_file:
        log_file.write(f"[{timestamp}] {message}\n")


CONFIG_FILE = 'settings.ini'


# ====================== MD5 Implementation ======================
class MD5:
    _rotate_amounts = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                       5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
                       4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                       6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21]

    _constants = [int(abs((2 ** 32) * abs(__import__('math').sin(i + 1)))) for i in range(64)]

    @staticmethod
    def left_rotate(x, amount):
        x &= 0xFFFFFFFF
        return ((x << amount) | (x >> (32 - amount))) & 0xFFFFFFFF

    @staticmethod
    def md5(message):
        if isinstance(message, str):
            message = message.encode('utf-8')
        message = bytearray(message)
        orig_len = (8 * len(message)) & 0xFFFFFFFFFFFFFFFF
        message.append(0x80)

        while len(message) % 64 != 56:
            message.append(0)

        message += orig_len.to_bytes(8, byteorder='little')

        a0 = 0x67452301
        b0 = 0xEFCDAB89
        c0 = 0x98BADCFE
        d0 = 0x10325476

        for chunk_ofst in range(0, len(message), 64):
            a, b, c, d = a0, b0, c0, d0
            chunk = message[chunk_ofst:chunk_ofst + 64]

            for i in range(64):
                if i < 16:
                    f = (b & c) | ((~b) & d)
                    g = i
                elif i < 32:
                    f = (d & b) | ((~d) & c)
                    g = (5 * i + 1) % 16
                elif i < 48:
                    f = b ^ c ^ d
                    g = (3 * i + 5) % 16
                else:
                    f = c ^ (b | (~d))
                    g = (7 * i) % 16

                to_rotate = a + f + MD5._constants[i] + int.from_bytes(chunk[4 * g:4 * g + 4], byteorder='little')
                new_b = (b + MD5.left_rotate(to_rotate, MD5._rotate_amounts[i])) & 0xFFFFFFFF
                a, b, c, d = d, new_b, b, c

            a0 = (a0 + a) & 0xFFFFFFFF
            b0 = (b0 + b) & 0xFFFFFFFF
            c0 = (c0 + c) & 0xFFFFFFFF
            d0 = (d0 + d) & 0xFFFFFFFF

        digest = (a0.to_bytes(4, byteorder='little') +
                  b0.to_bytes(4, byteorder='little') +
                  c0.to_bytes(4, byteorder='little') +
                  d0.to_bytes(4, byteorder='little'))

        return binascii.hexlify(digest).decode()


# ====================== Server Implementation ======================
def load_config():
    config = configparser.ConfigParser()
    if not os.path.exists(CONFIG_FILE):
        config['DEFAULT'] = {'Port': '7777'}
        with open(CONFIG_FILE, 'w') as configfile:
            config.write(configfile)
    config.read(CONFIG_FILE)
    return int(config['DEFAULT'].get('Port', '7777'))


def handle_client(client_socket, client_address, clients, usernames):
    try:
        name = client_socket.recv(1024).decode('utf-8').strip()
        if not 2 <= len(name) <= 30:
            client_socket.close()
            return

        welcome_message = "Добро пожаловать на наш чат!"
        client_socket.send(welcome_message.encode('utf-8'))
        broadcast_message(f"{name} присоединился к чату.", client_socket, clients)

        usernames[client_socket] = name
        clients.add(client_socket)

        while True:
            try:
                data = client_socket.recv(1024)
                if not data:
                    break

                if b'|||' in data:
                    parts = data.split(b'|||')
                    if len(parts) >= 3:
                        text_message, hash_message, key = parts[:3]
                        log_message(f"Получено сообщение от {name}:")
                        log_message(f"Зашифрованный текст: {text_message.hex()}")
                        log_message(f"Хеш: {hash_message.decode()}")
                        log_message(f"Ключ: {key.hex()}")
                        if random.randint(0, 10) < 3:
                            hash_message = hash_message.decode('utf-8')
                            hash_message = hash_message[:1] + 'X' + hash_message[2:]
                            hash_message = hash_message.encode('utf-8')

                        message = name.encode('utf-8') + b'|||' + text_message + b'|||' + hash_message + b'|||' + key
                        broadcast_message(message, client_socket, clients)

            except (ConnectionResetError, ConnectionAbortedError):
                break
            except Exception as e:
                print(f"Ошибка обработки сообщения: {e}")
                break

    except Exception as e:
        print(f"Ошибка в handle_client: {e}")
    finally:
        if client_socket in clients:
            clients.remove(client_socket)
        if client_socket in usernames:
            username = usernames[client_socket]
            broadcast_message(f"{username} покинул чат.", client_socket, clients)
            del usernames[client_socket]
        client_socket.close()


def broadcast_message(message, sender_socket, clients):
    for client in list(clients):
        if client != sender_socket:
            try:
                if isinstance(message, bytes):
                    # Логирование перед отправкой
                    if b'|||' in message:
                        parts = message.split(b'|||')
                        if len(parts) >= 4:
                            log_message(f"Отправка сообщения:")
                            log_message(f"Отправитель: {parts[0].decode()}")
                            log_message(f"Шифртекст: {parts[1].hex()}")
                            log_message(f"Хеш: {parts[2].decode()}")
                            log_message(f"Ключ: {parts[3].hex()}")

                    client.send(message)
                else:
                    client.send(message.encode('utf-8'))
            except (ConnectionResetError, ConnectionAbortedError):
                clients.discard(client)
            except Exception as e:
                print(f"Ошибка отправки сообщения: {e}")


def start_server():
    port = load_config()
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_socket.bind(('0.0.0.0', port))
        server_socket.listen()
        print(f"Сервер запущен на порту {port}")

        clients = set()
        usernames = {}

        while True:
            try:
                client_socket, client_address = server_socket.accept()
                threading.Thread(
                    target=handle_client,
                    args=(client_socket, client_address, clients, usernames),
                    daemon=True
                ).start()
            except Exception as e:
                print(f"Ошибка принятия подключения: {e}")

    except Exception as e:
        print(f"Ошибка сервера: {e}")
    finally:
        server_socket.close()


# ====================== Client Implementation ======================
def receive_messages(client_socket):
    while True:
        try:
            data = client_socket.recv(4096)
            if not data:
                print("\nСоединение с сервером разорвано")
                os._exit(0)

            if b'|||' in data:
                parts = data.split(b'|||')
                if len(parts) >= 4:
                    name, text_message, hash_message, key = parts[:4]

                    log_message(f"Клиент получил сообщение:")
                    log_message(f"От: {name.decode()}")
                    log_message(f"Шифртекст: {text_message.hex()}")
                    log_message(f"Ожидаемый хеш: {hash_message.decode()}")
                    log_message(f"Ключ: {key.hex()}")

                    computed_hash = MD5.md5(text_message)
                    log_message(f"Вычисленный хеш: {computed_hash}")

                    try:
                        computed_hash = MD5.md5(text_message)
                        received_hash = hash_message.decode('utf-8')

                        print(f"\n{name.decode('utf-8')}: ", end='')
                        print(text_message.decode('utf-8', errors='replace'))

                        if computed_hash != received_hash:
                            print("(Сообщение было повреждено при передаче)")
                        else:
                            print("(Сообщение доставлено без ошибок)")
                    except Exception as e:
                        print(f"\nОшибка декодирования сообщения: {e}")
                else:
                    print("\nПолучено некорректное сообщение от сервера")
            else:
                print(data.decode('utf-8', errors='replace'))

        except (ConnectionResetError, ConnectionAbortedError):
            print("\nСоединение с сервером разорвано")
            os._exit(0)
        except Exception as e:
            print(f"\nОшибка приема сообщения: {e}")
            os._exit(1)


def start_client():
    while True:
        name = input("Введите имя (2-30 символов): ").strip()
        if 2 <= len(name) <= 30:
            break
        print("Неверная длина имени. Попробуйте снова.")

    while True:
        try:
            server_ip = input("Введите IP сервера [127.0.0.1]: ").strip() or "127.0.0.1"
            server_port = input("Введите порт сервера [7777]: ").strip() or "7777"
            server_port = int(server_port)

            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((server_ip, server_port))
            break
        except ValueError:
            print("Неверный порт. Введите число.")
        except Exception as e:
            print(f"Ошибка подключения: {e}. Попробуйте снова.")

    client_socket.send(name.encode('utf-8'))

    threading.Thread(target=receive_messages, args=(client_socket,), daemon=True).start()

    try:
        while True:
            message = input()
            if message.lower() == 'exit':
                break

            if 1 <= len(message) <= 80:
                try:
                    encrypted_msg = message.encode('utf-8')
                    msg_hash = MD5.md5(encrypted_msg)
                    key = os.urandom(32)

                    log_message(f"Клиент отправляет сообщение:")
                    log_message(f"Исходный текст: {message}")
                    log_message(f"Шифртекст: {encrypted_msg.hex()}")
                    log_message(f"Хеш: {msg_hash}")
                    log_message(f"Ключ: {key.hex()}")

                    data = encrypted_msg + b'|||' + msg_hash.encode('utf-8') + b'|||' + key
                    client_socket.send(data)
                except Exception as e:
                    print(f"Ошибка отправки сообщения: {e}")
            else:
                print("Сообщение должно содержать от 1 до 80 символов")

    except (EOFError, KeyboardInterrupt):
        print("\nЗавершение работы...")
    finally:
        client_socket.close()
        os._exit(0)


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1].lower() == 'server':
        start_server()
    else:
        start_client()