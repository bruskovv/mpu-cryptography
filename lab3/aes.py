"""AES-128: зашифрование и расшифрование одного 128-битного блока.

Реализованы развёртывание ключа, четыре раундовых преобразования
(SubBytes, ShiftRows, MixColumns, AddRoundKey) и все обратные операции.
"""

from config import config

# Таблица подстановки AES (S-бокс) и обратная к ней: 256 байтов.
SBOX = tuple(bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16"
))

INV_SBOX = tuple(bytes.fromhex(
    "52096ad53036a538bf40a39e81f3d7fb7ce339829b2fff87348e4344c4dee9cb"
    "547b9432a6c2233dee4c950b42fac34e082ea16628d924b2765ba2496d8bd125"
    "72f8f66486689816d4a45ccc5d65b6926c704850fdedb9da5e154657a78d9d84"
    "90d8ab008cbcd30af7e45805b8b34506d02c1e8fca3f0f02c1afbd0301138a6b"
    "3a9111414f67dcea97f2cfcef0b4e67396ac7422e7ad3585e2f937e81c75df6e"
    "47f11a711d29c5896fb7620eaa18be1bfc563e4bc6d279209adbc0fe78cd5af4"
    "1fdda8338807c731b11210592780ec5f60517fa919b54a0d2de57a9f93c99cef"
    "a0e03b4dae2af5b0c8ebbb3c83539961172b047eba77d626e169146355210c7d"
))

RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


def _check_bytes(value, size, name):
    """Проверяет, что значение — байтовая строка нужной длины."""
    if not isinstance(value, (bytes, bytearray)):
        raise ValueError(f"{name} должен быть набором байтов")
    if len(value) != size:
        raise ValueError(f"{name}: ожидалось {size} байтов, получено {len(value)}")


def _xtime(value):
    """Умножение на x в поле GF(2^8) по модулю x^8 + x^4 + x^3 + x + 1."""
    value <<= 1
    if value & 0x100:
        value ^= 0x11B
    return value & 0xFF


def multiply(left, right):
    """Умножение двух байтов в GF(2^8)."""
    result = 0
    while right:
        if right & 1:
            result ^= left
        left = _xtime(left)
        right >>= 1
    return result


def expand_key(key):
    """Развёртывание ключа: 11 раундовых ключей по 16 байтов."""
    _check_bytes(key, config.aes_key_bytes, "Ключ AES")
    words = [list(key[4 * i:4 * i + 4]) for i in range(4)]
    for index in range(4, 4 * (config.aes_rounds + 1)):
        temp = list(words[index - 1])
        if index % 4 == 0:
            temp = temp[1:] + temp[:1]              # RotWord
            temp = [SBOX[byte] for byte in temp]    # SubWord
            temp[0] ^= RCON[index // 4 - 1]         # Rcon
        words.append([words[index - 4][i] ^ temp[i] for i in range(4)])
    return [sum(words[4 * round_index:4 * round_index + 4], [])
            for round_index in range(config.aes_rounds + 1)]


def _add_round_key(state, round_key):
    for index in range(len(state)):
        state[index] ^= round_key[index]


def _sub_bytes(state, table):
    for index, byte in enumerate(state):
        state[index] = table[byte]


def _shift_rows(state):
    """Строка r сдвигается влево на r байт; нулевая строка стоит на месте."""
    for row in range(1, 4):
        values = [state[row + 4 * column] for column in range(4)]
        for column in range(4):
            state[row + 4 * column] = values[(column + row) % 4]


def _inv_shift_rows(state):
    for row in range(1, 4):
        values = [state[row + 4 * column] for column in range(4)]
        for column in range(4):
            state[row + 4 * column] = values[(column - row) % 4]


def _mix_columns(state):
    """Каждый столбец умножается на полином 03 01 01 02 в GF(2^8)."""
    for column in range(4):
        a0, a1, a2, a3 = (state[row + 4 * column] for row in range(4))
        state[0 + 4 * column] = multiply(a0, 2) ^ multiply(a1, 3) ^ a2 ^ a3
        state[1 + 4 * column] = a0 ^ multiply(a1, 2) ^ multiply(a2, 3) ^ a3
        state[2 + 4 * column] = a0 ^ a1 ^ multiply(a2, 2) ^ multiply(a3, 3)
        state[3 + 4 * column] = multiply(a0, 3) ^ a1 ^ a2 ^ multiply(a3, 2)


def _inv_mix_columns(state):
    for column in range(4):
        a0, a1, a2, a3 = (state[row + 4 * column] for row in range(4))
        state[0 + 4 * column] = (multiply(a0, 14) ^ multiply(a1, 11)
                                 ^ multiply(a2, 13) ^ multiply(a3, 9))
        state[1 + 4 * column] = (multiply(a0, 9) ^ multiply(a1, 14)
                                 ^ multiply(a2, 11) ^ multiply(a3, 13))
        state[2 + 4 * column] = (multiply(a0, 13) ^ multiply(a1, 9)
                                 ^ multiply(a2, 14) ^ multiply(a3, 11))
        state[3 + 4 * column] = (multiply(a0, 11) ^ multiply(a1, 13)
                                 ^ multiply(a2, 9) ^ multiply(a3, 14))


def aes_encrypt_block(block, key):
    """Зашифровывает один блок (16 байтов)."""
    _check_bytes(block, config.aes_block_bytes, "Блок AES")
    round_keys = expand_key(key)
    state = list(block)
    _add_round_key(state, round_keys[0])

    for round_index in range(1, config.aes_rounds):
        _sub_bytes(state, SBOX)
        _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, round_keys[round_index])

    # Последний раунд — без MixColumns.
    _sub_bytes(state, SBOX)
    _shift_rows(state)
    _add_round_key(state, round_keys[config.aes_rounds])
    return bytes(state)


def aes_decrypt_block(block, key):
    """Расшифровывает один блок: обратные преобразования и ключи в обратном порядке."""
    _check_bytes(block, config.aes_block_bytes, "Блок AES")
    round_keys = expand_key(key)
    state = list(block)
    _add_round_key(state, round_keys[config.aes_rounds])

    for round_index in range(config.aes_rounds - 1, 0, -1):
        _inv_shift_rows(state)
        _sub_bytes(state, INV_SBOX)
        _add_round_key(state, round_keys[round_index])
        _inv_mix_columns(state)

    _inv_shift_rows(state)
    _sub_bytes(state, INV_SBOX)
    _add_round_key(state, round_keys[0])
    return bytes(state)


def aes_encrypt_hex(block_hex, key_hex):
    """Шифрование блока, заданного шестнадцатеричной строкой."""
    return aes_encrypt_block(bytes.fromhex(block_hex), bytes.fromhex(key_hex)).hex()


def aes_decrypt_hex(block_hex, key_hex):
    """Расшифрование блока, заданного шестнадцатеричной строкой."""
    return aes_decrypt_block(bytes.fromhex(block_hex), bytes.fromhex(key_hex)).hex()


if __name__ == "__main__":
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plain = bytes.fromhex("00112233445566778899aabbccddeeff")

    cipher = aes_encrypt_block(plain, key)
    print("AES-128")
    print("ключ         :", key.hex())
    print("открытый блок:", plain.hex())
    print("шифроблок    :", cipher.hex())
    print("расшифровка  :", aes_decrypt_block(cipher, key).hex())
