"""RC4: потоковый шифр, генератор гаммы и шифрование сообщения любой длины.

Гамма вырабатывается генератором ключевого потока: сначала массив S
перемешивается ключом (KSA), затем из него побайтово берётся гамма (PRGA).
"""

from config import config


def _check_key(key):
    """Ключ RC4 — от 1 до 256 байтов."""
    if not isinstance(key, (bytes, bytearray)):
        raise ValueError("Ключ RC4 должен быть набором байтов")
    if not config.rc4_min_key_bytes <= len(key) <= config.rc4_max_key_bytes:
        raise ValueError("Длина ключа RC4 должна быть от 1 до 256 байтов")


def _check_data(data):
    if not isinstance(data, (bytes, bytearray)):
        raise ValueError("Данные должны быть набором байтов")


def ksa(key):
    """Key Scheduling Algorithm: перемешивает массив S ключом."""
    _check_key(key)
    state = list(range(config.rc4_state_size))
    shift = 0
    for index in range(config.rc4_state_size):
        shift = (shift + state[index] + key[index % len(key)]) % config.rc4_state_size
        state[index], state[shift] = state[shift], state[index]
    return state


def prga(state, length):
    """Pseudo-Random Generation Algorithm: выдаёт гамму нужной длины.

    Массив S меняется по ходу работы, поэтому для расшифрования генератор
    надо начать с того же состояния — то есть с той же ключевой установки.
    """
    index = 0
    shift = 0
    gamma = bytearray()
    for _ in range(length):
        index = (index + 1) % config.rc4_state_size
        shift = (shift + state[index]) % config.rc4_state_size
        state[index], state[shift] = state[shift], state[index]
        gamma.append(state[(state[index] + state[shift]) % config.rc4_state_size])
    return bytes(gamma)


def rc4_keystream(key, length, offset=0):
    """Первые `length` байтов гаммы после `offset` пропущенных байтов.

    Пропуск нужен только для сверки с контрольными примерами RFC 6229,
    где гамма печатается с разных смещений.
    """
    state = ksa(key)
    if offset:
        prga(state, offset)
    return prga(state, length)


def rc4_crypt(data, key):
    """Шифрование и расшифрование — одна и та же операция XOR с гаммой."""
    _check_data(data)
    gamma = rc4_keystream(key, len(data))
    return bytes(byte ^ mask for byte, mask in zip(data, gamma))


def rc4_encrypt_text(text, key):
    """Шифрует строку в UTF-8 и возвращает шестнадцатеричную строку."""
    if not isinstance(text, str):
        raise ValueError("Текст должен быть строкой")
    return rc4_crypt(text.encode("utf-8"), key).hex()


def rc4_decrypt_text(cipher_hex, key):
    """Расшифровывает шестнадцатеричную строку обратно в текст."""
    if not isinstance(cipher_hex, str):
        raise ValueError("Шифротекст должен быть строкой в hex")
    try:
        data = bytes.fromhex(cipher_hex)
    except ValueError as error:
        raise ValueError("Шифротекст должен быть строкой в hex без посторонних символов") from error
    return rc4_crypt(data, key).decode("utf-8")


if __name__ == "__main__":
    key = b"Key"
    text = "Plaintext"

    print("RC4")
    print("ключ         :", key.decode())
    print("гамма (16)   :", rc4_keystream(key, 16).hex())
    print("открытый текст:", text)
    print("шифротекст   :", rc4_encrypt_text(text, key))
    print("расшифровка  :", rc4_decrypt_text(rc4_encrypt_text(text, key), key))
