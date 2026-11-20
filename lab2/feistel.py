from config import config

MASK8 = 0xFF
MASK16 = 0xFFFF


def _check_key(key) -> str:
    """Ключ должен быть непустой строкой."""
    if not isinstance(key, str):
        raise ValueError("Ключ должен быть строкой")
    key = key.strip()
    if not key:
        raise ValueError("Ключ не должен быть пустым")
    return key


def _rotate_left(value: int, shift: int, bits: int) -> int:
    """Циклический сдвиг влево внутри заданного числа битов."""
    mask = (1 << bits) - 1
    shift %= bits
    value &= mask
    return ((value << shift) | (value >> (bits - shift))) & mask


def derive_master_key(key: str) -> int:
    """Свернуть ключ-строку в 16-битное значение.

    Байты ключа складываются по XOR с циклическим сдвигом, поэтому
    ключ любой длины превращается в одно 16-битное число.
    """
    key = _check_key(key)
    master = 0
    for byte in key.encode("utf-8"):
        master = _rotate_left(master ^ byte, config.key_shift, config.block_bits)
    return master


def generate_subkeys(master_key: int) -> list[int]:
    """Сформировать по одному 8-битному подключу на раунд.

    Сначала мастер-ключ умножается на нечётную константу: умножение
    перемешивает старшие и младшие биты, поэтому изменение любого бита
    ключа меняет подключи, а не только «свою» половину.
    """
    subkeys = []
    master = master_key & MASK16
    for round_index in range(config.rounds):
        # умножаем, берём старшую половину результата (8 бит)
        mixed = ((master * config.master_mix) >> config.half_bits) & MASK8
        # разводим раунды константой и сдвигаем
        subkey = _rotate_left(mixed ^ (round_index * config.subkey_step),
                              config.key_shift, config.half_bits)
        subkeys.append(subkey)
        # следующее значение мастера — сдвиг на бит, подключи не повторяются
        master = _rotate_left(master, 1, config.block_bits)
    return subkeys


def _f_function(right_half: int, subkey: int) -> int:
    """Раундовая функция F: XOR с подключом, сложение с переносом и сдвиг.

    Сложение по модулю 256 нужно, чтобы переносы разносили изменение одного
    бита по соседним. При одном только XOR со сдвигом функция остаётся
    линейной по ключу, и на некоторых числах раундов ключ перестаёт влиять
    на результат — это было видно при отладке.
    """
    mixed = (right_half ^ subkey) & MASK8
    mixed = (mixed + subkey) & MASK8
    return _rotate_left(mixed, config.f_shift, config.half_bits)


def _xor(left: int, right: int) -> int:
    return (left ^ right) & MASK8


def _encrypt_block(block: int, subkeys: list[int]) -> int:
    """Один блок 16 бит: раунды сети Фейстеля и финальная перестановка половин."""
    left = (block >> config.half_bits) & MASK8
    right = block & MASK8

    for subkey in subkeys:
        left, right = right, _xor(left, _f_function(right, subkey))

    # после последнего раунда половины меняются местами — это часть схемы
    return (right << config.half_bits) | left


def _decrypt_block(block: int, subkeys: list[int]) -> int:
    """Обратный ход: подключи в обратном порядке, половины возвращаются на места.

    Для раунда Li = Ri-1, Ri = Li-1 XOR F(Ri-1, Ki) обратный ход такой:
    Ri-1 = Li,  Li-1 = Ri XOR F(Li, Ki).
    """
    # в шифроблоке половины уже переставлены: старший байт — R_n, младший — L_n
    left = block & MASK8
    right = (block >> config.half_bits) & MASK8

    for subkey in reversed(subkeys):
        left, right = _xor(right, _f_function(left, subkey)), left

    return (left << config.half_bits) | right


def _pad(data: bytes) -> bytes:
    """Дополнение по схеме PKCS#7: значение байта = сколько байт добавлено."""
    remainder = len(data) % config.block_bytes
    pad_length = config.block_bytes - remainder
    return data + bytes([pad_length]) * pad_length


def _unpad(data: bytes) -> bytes:
    """Снять дополнение и проверить, что оно корректное."""
    if not data or len(data) % config.block_bytes != 0:
        raise ValueError("Длина данных должна быть кратна размеру блока (2 байта)")

    pad_length = data[-1]
    if not 1 <= pad_length <= config.block_bytes:
        raise ValueError("Некорректное дополнение: неверный ключ или повреждён шифротекст")
    if data[-pad_length:] != bytes([pad_length]) * pad_length:
        raise ValueError("Некорректное дополнение: неверный ключ или повреждён шифротекст")
    return data[:-pad_length]


def encrypt_bytes(data: bytes, master_key: int) -> bytes:
    """Зашифровать произвольные байты 16-битными блоками."""
    subkeys = generate_subkeys(master_key)
    padded = _pad(data)
    result = bytearray()

    for start in range(0, len(padded), config.block_bytes):
        block = int.from_bytes(padded[start:start + config.block_bytes], "big")
        cipher_block = _encrypt_block(block, subkeys)
        result += cipher_block.to_bytes(config.block_bytes, "big")

    return bytes(result)


def decrypt_bytes(data: bytes, master_key: int) -> bytes:
    """Расшифровать байты, полученные encrypt_bytes."""
    subkeys = generate_subkeys(master_key)
    if not data or len(data) % config.block_bytes != 0:
        raise ValueError("Длина шифротекста должна быть кратна размеру блока (2 байта)")

    result = bytearray()
    for start in range(0, len(data), config.block_bytes):
        block = int.from_bytes(data[start:start + config.block_bytes], "big")
        plain_block = _decrypt_block(block, subkeys)
        result += plain_block.to_bytes(config.block_bytes, "big")

    return _unpad(bytes(result))


def feistel_encrypt(text: str, key: str) -> str:
    """Зашифровать текст, вернуть шифротекст в hex."""
    if not isinstance(text, str):
        raise ValueError("Текст должен быть строкой")
    master_key = derive_master_key(key)
    return encrypt_bytes(text.encode("utf-8"), master_key).hex()


def feistel_decrypt(cipher_hex: str, key: str) -> str:
    """Расшифровать hex-шифротекст, вернуть текст."""
    if not isinstance(cipher_hex, str):
        raise ValueError("Шифротекст должен быть строкой в hex")
    try:
        data = bytes.fromhex(cipher_hex.strip())
    except ValueError:
        raise ValueError("Шифротекст должен быть строкой в hex без посторонних символов")

    master_key = derive_master_key(key)
    return decrypt_bytes(data, master_key).decode("utf-8")


if __name__ == "__main__":
    print(feistel_encrypt("Hello", "key"))
    print(feistel_decrypt(feistel_encrypt("Hello", "key"), "key"))

