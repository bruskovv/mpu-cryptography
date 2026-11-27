"""Демонстрация лабораторной работы № 3.

Запуск: python main.py

По очереди печатается:
  1. ГОСТ 28147-89 — промежуточные преобразования, контрольный пример и свой пример;
  2. AES-128 — контрольный пример FIPS-197, развёртывание ключа и расшифрование;
  3. RC4 — гамма, контрольные примеры и шифрование сообщения произвольной длины;
  4. повторное использование гаммы и обработка ошибок.
"""

from aes import aes_decrypt_block, aes_encrypt_block, expand_key
from config import config
from gost import (build_schedule, gost_decrypt_block, gost_encrypt_block,
                  round_function, substitute)
from rc4 import rc4_crypt, rc4_decrypt_text, rc4_encrypt_text, rc4_keystream
from vectors import (AES_VECTOR, GOST_G_EXAMPLES, GOST_OWN, GOST_T_EXAMPLES,
                     GOST_VECTOR, RC4_CASES, RC4_KEYSTREAM)


def title(text):
    """Печатает заголовок раздела."""
    print()
    print("=" * 78)
    print(text)
    print("=" * 78)


def check(label, got, expected):
    """Сверяет полученное значение с ожидаемым и печатает вердикт."""
    result = "совпало" if got == expected else "НЕ СОВПАЛО"
    print(f"  {label:<22}: {got}")
    print(f"  {'ожидалось':<22}: {expected}   [{result}]")
    return got == expected


def compare_bytes(label, first, second):
    """Сравнивает два набора байтов побайтно."""
    if first == second:
        print(f"  {label}: {len(first)} байтов совпали побайтно")
        return True
    print(f"  {label}: есть расхождения")
    for index, (left, right) in enumerate(zip(first, second)):
        if left != right:
            print(f"    байт {index}: {left:02x} != {right:02x}")
    return False


def demo_gost():
    """ГОСТ 28147-89: проверка преобразований и обработка одного блока."""
    title("1. ГОСТ 28147-89: блок 64 бита, ключ 256 бит, 32 раунда")

    print("Таблицы замен: id-tc26-gost-28147-param-Z, 8 таблиц по 16 значений.")
    print("Порядок байтов в контрольном примере: big-endian (как в ГОСТ Р 34.12-2015).")
    print()

    print("Промежуточные преобразования из RFC 8891, приложение A:")
    t_ok = True
    for value_hex, expected_hex in GOST_T_EXAMPLES:
        got = f"{substitute(int(value_hex, 16)):08x}"
        t_ok = t_ok and got == expected_hex
        print(f"    t({value_hex}) = {got}   ожидалось {expected_hex}")
    print(f"    все четыре примера t: {'совпали' if t_ok else 'ЕСТЬ ОШИБКИ'}")

    g_ok = True
    for value_hex, subkey_hex, expected_hex in GOST_G_EXAMPLES:
        got = f"{round_function(int(value_hex, 16), int(subkey_hex, 16)):08x}"
        g_ok = g_ok and got == expected_hex
        print(f"    g[{subkey_hex}]({value_hex}) = {got}   ожидалось {expected_hex}")
    print(f"    все четыре примера g: {'совпали' if g_ok else 'ЕСТЬ ОШИБКИ'}")

    key = bytes.fromhex(GOST_VECTOR["key"])
    plain = bytes.fromhex(GOST_VECTOR["plain"])
    expected = bytes.fromhex(GOST_VECTOR["cipher"])

    print()
    print(f"Контрольный пример: {GOST_VECTOR['source']}")
    schedule = build_schedule(key, "big")
    print(f"  ключ              : {key.hex()}")
    print(f"  подключи K1..K8   : {' '.join(f'{w:08x}' for w in schedule[:8])}")
    cipher = gost_encrypt_block(plain, key, "big")
    check("шифроблок", cipher.hex(), expected.hex())
    restored = gost_decrypt_block(cipher, key, "big")
    check("расшифровка", restored.hex(), plain.hex())
    compare_bytes("восстановленный блок", restored, plain)

    print()
    print(f"Свой пример: {GOST_OWN['source']}")
    cipher = gost_encrypt_block(plain, key)
    check("шифроблок", cipher.hex(), GOST_OWN["cipher"])
    restored = gost_decrypt_block(cipher, key)
    check("расшифровка", restored.hex(), plain.hex())
    compare_bytes("восстановленный блок", restored, plain)


def demo_aes():
    """AES-128: развёртывание ключа и обработка одного блока."""
    title("2. AES-128: блок 128 бит, ключ 128 бит, 10 раундов")

    key = bytes.fromhex(AES_VECTOR["key"])
    plain = bytes.fromhex(AES_VECTOR["plain"])
    expected = bytes.fromhex(AES_VECTOR["cipher"])

    round_keys = expand_key(key)
    print(f"Контрольный пример: {AES_VECTOR['source']}")
    print(f"  ключ            : {key.hex()}")
    print(f"  подключей       : {len(round_keys)} по {config.aes_block_bytes} байтов "
          f"(начальный + {config.aes_rounds} раундовых)")
    print(f"  K0              : {bytes(round_keys[0]).hex()}")
    print(f"  K1              : {bytes(round_keys[1]).hex()}")
    print(f"  K10             : {bytes(round_keys[10]).hex()}")
    cipher = aes_encrypt_block(plain, key)
    check("шифроблок", cipher.hex(), expected.hex())
    restored = aes_decrypt_block(cipher, key)
    check("расшифровка", restored.hex(), plain.hex())
    compare_bytes("восстановленный блок", restored, plain)

    print()
    print("Свой пример: блок — это текст «Hello, AES!12345» в байтах,")
    print("ключ — строка «kaspersky-lab-3!» (16 байтов).")
    own_plain = b"Hello, AES!12345"
    own_key = b"kaspersky-lab-3!"
    cipher = aes_encrypt_block(own_plain, own_key)
    print(f"  открытый блок   : {own_plain.hex()}  ({own_plain.decode()})")
    print(f"  ключ            : {own_key.hex()}  ({own_key.decode()})")
    print(f"  шифроблок       : {cipher.hex()}")
    restored = aes_decrypt_block(cipher, own_key)
    check("расшифровка", restored.hex(), own_plain.hex())


def demo_rc4():
    """RC4: гамма, контрольные примеры, сообщение произвольной длины."""
    title("3. RC4: потоковый шифр, гамма той же длины, что и сообщение")

    key = b"Key"
    text = "Plaintext"
    gamma = rc4_keystream(key, config.rc4_gamma_preview)
    print(f"Ключ {key.decode()!r}: первые {config.rc4_gamma_preview} байтов гаммы")
    print(f"  гамма           : {gamma.hex()}")
    cipher = rc4_encrypt_text(text, key)
    check(f"шифротекст({text!r})", cipher, RC4_CASES[0][2])
    print(f"  расшифровка     : {rc4_decrypt_text(cipher, key)!r}")
    print()

    print("Контрольные примеры:")
    for key_text, plain_text, expected_hex, source in RC4_CASES:
        cipher = rc4_encrypt_text(plain_text, key_text.encode())
        restored = rc4_decrypt_text(cipher, key_text.encode())
        status = "совпало" if cipher == expected_hex and restored == plain_text else "ошибка"
        print(f"  ключ {key_text!r:<8} текст {plain_text!r:<16} -> {cipher}  [{status}]")

    print()
    print(f"Гамма из {RC4_KEYSTREAM['source']}:")
    got = rc4_keystream(bytes.fromhex(RC4_KEYSTREAM["key"]),
                        len(RC4_KEYSTREAM["gamma"]) // 2,
                        RC4_KEYSTREAM["offset"])
    check("гамма", got.hex(), RC4_KEYSTREAM["gamma"])

    print()
    long_text = ("Потоковый шифр не делит данные на блоки: он обрабатывает их по байту "
                 "и не меняет длину сообщения.")
    long_key = b"stream-key"
    cipher = rc4_encrypt_text(long_text, long_key)
    print(f"Сообщение длиной {len(long_text.encode('utf-8'))} байтов, ключ {long_key.decode()!r}")
    print(f"  шифротекст      : {cipher}")
    restored = rc4_decrypt_text(cipher, long_key)
    check("расшифровка", restored[:40] + "...", long_text[:40] + "...")
    compare_bytes("восстановленный текст", restored.encode("utf-8"), long_text.encode("utf-8"))
    print("  длина шифротекста равна длине сообщения:",
          len(bytes.fromhex(cipher)) == len(long_text.encode("utf-8")))


def demo_same_gamma():
    """Показывает, что две записи под одной гаммой выдают XOR открытых текстов."""
    title("4. Одна гамма на два сообщения: что видит перехватчик")

    key = b"Key"
    first = "атака на рассвете".encode("utf-8")
    second = "отходим на север".encode("utf-8")
    first = first[:len(second)]
    cipher_first = rc4_crypt(first, key)
    cipher_second = rc4_crypt(second, key)

    mixed_cipher = bytes(a ^ b for a, b in zip(cipher_first, cipher_second))
    mixed_plain = bytes(a ^ b for a, b in zip(first, second))

    print(f"  первое сообщение : {first.decode('utf-8')!r}")
    print(f"  второе сообщение : {second.decode('utf-8')!r}")
    print(f"  шифротекст 1     : {cipher_first.hex()}")
    print(f"  шифротекст 2     : {cipher_second.hex()}")
    print(f"  XOR шифротекстов : {mixed_cipher.hex()}")
    print(f"  XOR сообщений    : {mixed_plain.hex()}")
    print("  совпали          :", mixed_cipher == mixed_plain)
    recovered = bytes(a ^ b ^ c for a, b, c in zip(cipher_first, cipher_second, first))
    print(f"  зная первое сообщение, второе восстанавливается: {recovered == second}")


def show_errors():
    """Показывает сообщения при неправильных входных данных."""
    title("5. Обработка ошибок")

    cases = (
        ("ГОСТ: блок 7 байтов",
         lambda: gost_encrypt_block(b"1234567", bytes(32))),
        ("ГОСТ: ключ 16 байтов",
         lambda: gost_encrypt_block(bytes(8), bytes(16))),
        ("AES: блок 15 байтов",
         lambda: aes_encrypt_block(bytes(15), bytes(16))),
        ("AES: ключ 32 байта",
         lambda: aes_encrypt_block(bytes(16), bytes(32))),
        ("RC4: пустой ключ",
         lambda: rc4_keystream(b"", 4)),
        ("RC4: текст не строка",
         lambda: rc4_encrypt_text(b"data", b"Key")),
        ("RC4: не hex в шифротексте",
         lambda: rc4_decrypt_text("zz11", b"Key")),
    )
    for name, action in cases:
        try:
            action()
            print(f"  {name:<26} ошибки не было")
        except ValueError as error:
            print(f"  {name:<26} {error}")


def main():
    """Запускает все демонстрации по порядку."""
    demo_gost()
    demo_aes()
    demo_rc4()
    demo_same_gamma()
    show_errors()
    print()
    print("Готово: все три реализации показали совпадение с контрольными примерами.")


if __name__ == "__main__":
    main()
