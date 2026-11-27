"""ГОСТ 28147-89: зашифрование и расшифрование одного 64-битного блока.

Реализована сеть Фейстеля: 32 раунда, ключ 256 бит (восемь 32-битных подключей),
таблицы замен 8 x 16 и циклический сдвиг на 11 бит.
"""

from config import config

MASK32 = 0xFFFFFFFF


def _check_bytes(value, size, name):
    """Проверяет, что значение — байтовая строка нужной длины."""
    if not isinstance(value, (bytes, bytearray)):
        raise ValueError(f"{name} должен быть набором байтов")
    if len(value) != size:
        raise ValueError(f"{name}: ожидалось {size} байтов, получено {len(value)}")


def _to_words(data, byte_order):
    """Режет байты на 32-битные слова в заданном порядке байтов."""
    return [int.from_bytes(data[i:i + 4], byte_order) for i in range(0, len(data), 4)]


def _to_bytes(words, byte_order):
    """Собирает слова обратно в байты."""
    return b"".join(word.to_bytes(4, byte_order) for word in words)


def _rotate_left(value, shift=None, bits=32):
    """Циклический сдвиг влево внутри 32 бит."""
    shift = config.gost_rotate if shift is None else shift
    mask = (1 << bits) - 1
    value &= mask
    return ((value << shift) | (value >> (bits - shift))) & mask


def substitute(value):
    """Таблицы замен: каждый 4-битный кусок проходит через свою таблицу.

    Младший кусок (биты 0-3) обрабатывается таблицей S1, следующий — S2 и так далее.
    На выходе снова 32 бита.
    """
    result = 0
    for index, table in enumerate(config.gost_sbox):
        part = (value >> (4 * index)) & 0xF
        result |= table[part] << (4 * index)
    return result


def round_function(value, subkey):
    """Раундовая функция g: сложение по модулю 2^32, замены, сдвиг на 11."""
    mixed = (value + subkey) & MASK32
    return _rotate_left(substitute(mixed))


def build_schedule(key, byte_order=None, for_decryption=False):
    """Раскладывает 256-битный ключ в последовательность из 32 подключей.

    Для зашифрования: K1..K8 трижды, затем K8..K1 — так требует стандарт.
    Для расшифрования берётся та же последовательность в обратном порядке.
    """
    order = byte_order or config.gost_byte_order
    _check_bytes(key, config.gost_key_bytes, "Ключ ГОСТ")
    words = _to_words(key, order)
    encryption = words * 3 + words[::-1]
    return encryption[::-1] if for_decryption else encryption


def _run_rounds(block, schedule, byte_order):
    """Общий цикл раундов; после последнего раунда половины меняются местами."""
    left, right = _to_words(block, byte_order)
    for subkey in schedule:
        left, right = right, left ^ round_function(right, subkey)
    return _to_bytes([right, left], byte_order)


def gost_encrypt_block(block, key, byte_order=None):
    """Зашифровывает один блок (8 байтов) ключом (32 байта)."""
    order = byte_order or config.gost_byte_order
    _check_bytes(block, config.gost_block_bytes, "Блок ГОСТ")
    return _run_rounds(block, build_schedule(key, order), order)


def gost_decrypt_block(block, key, byte_order=None):
    """Расшифровывает один блок: те же раунды, подключи в обратном порядке."""
    order = byte_order or config.gost_byte_order
    _check_bytes(block, config.gost_block_bytes, "Блок ГОСТ")
    schedule = build_schedule(key, order, for_decryption=True)
    return _run_rounds(block, schedule, order)


def gost_encrypt_hex(block_hex, key_hex, byte_order=None):
    """То же, но на входе и выходе шестнадцатеричные строки."""
    return gost_encrypt_block(bytes.fromhex(block_hex), bytes.fromhex(key_hex),
                              byte_order).hex()


def gost_decrypt_hex(block_hex, key_hex, byte_order=None):
    """Расшифрование в шестнадцатеричном виде."""
    return gost_decrypt_block(bytes.fromhex(block_hex), bytes.fromhex(key_hex),
                              byte_order).hex()


if __name__ == "__main__":
    key = bytes.fromhex("ffeeddccbbaa99887766554433221100"
                        "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    plain = bytes.fromhex("fedcba9876543210")

    cipher = gost_encrypt_block(plain, key)
    print("ГОСТ 28147-89, порядок байтов little-endian")
    print("открытый блок:", plain.hex())
    print("шифроблок    :", cipher.hex())
    print("расшифровка  :", gost_decrypt_block(cipher, key).hex())
    print()
    print("тот же блок в порядке Магмы (big-endian):",
          gost_encrypt_block(plain, key, "big").hex())
