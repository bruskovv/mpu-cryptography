from avalanche import (diff_bits, key_avalanche_table, rounds_experiment,
                       summarize, text_avalanche_table)
from feistel import derive_master_key, feistel_decrypt, feistel_encrypt


def demo(name: str, text: str, key: str) -> None:
    cipher = feistel_encrypt(text, key)
    decrypted = feistel_decrypt(cipher, key)

    print(f"=== {name} ===")
    print(f"открытый текст : {text!r}")
    print(f"ключ           : {key!r}")
    print(f"мастер-ключ    : 0x{derive_master_key(key):04x}")
    print(f"шифротекст     : {cipher}")
    print(f"расшифровка    : {decrypted!r}")
    print(f"D(E(m)) = m    : {decrypted == text}")
    print()


def show_avalanche(title: str, rows: list[tuple[int, str, str, int]]) -> None:
    print(f"=== {title} ===")
    print(f"{'бит':>3}  {'шифротекст 1':<20} {'шифротекст 2':<20} отличий")
    for bit_index, first, second, difference in rows:
        print(f"{bit_index:>3}  {first:<20} {second:<20} {difference}")

    stats = summarize(rows)
    print(f"блок {stats['block_bits']} бит; отличий: мин {stats['minimum']}, "
          f"макс {stats['maximum']}, среднее {stats['average']} "
          f"({stats['percent']} % битов блока)")
    print()


def show_rounds(text: str, key: str) -> None:
    print(f"=== Лавинный эффект и число раундов (текст {text!r}, ключ {key!r}) ===")
    print(f"{'раундов':>7}  {'бит текста':>11}  {'бит ключа':>10}")
    for rounds, text_average, key_average in rounds_experiment(text, key, [4, 6, 8, 12, 16]):
        print(f"{rounds:>7}  {text_average:>11}  {key_average:>10}")
    print()


def show_errors() -> None:
    print("=== Проверка некорректных данных ===")
    cases = [
        ("пустой ключ", lambda: feistel_encrypt("Hi", "   ")),
        ("ключ не строка", lambda: feistel_encrypt("Hi", 123)),
        ("не hex в шифротексте", lambda: feistel_decrypt("zz11", "key")),
        ("нечётная длина шифротекста", lambda: feistel_decrypt("abc", "key")),
        ("неверный ключ", lambda: feistel_decrypt(feistel_encrypt("Hi", "key"), "ключ")),
    ]
    for name, action in cases:
        try:
            action()
            print(f"{name:28} -> ошибки не было")
        except ValueError as error:
            print(f"{name:28} -> ValueError: {error}")
    print()


if __name__ == "__main__":
    demo("Латиница, ровно один блок", "Hi", "secret")
    demo("Кириллица", "Криптография", "шифр")
    demo("Короткий текст", "A", "k")
    demo("Длинный текст", "Блочное шифрование — это интересно", "пароль")

    show_avalanche("Лавинный эффект: меняем бит текста «Hi»",
                   text_avalanche_table("Hi", "secret"))
    show_avalanche("Лавинный эффект: меняем бит ключа «secret»",
                   key_avalanche_table("Hi", "secret"))
    show_rounds("Hi", "secret")
    show_errors()

    print("контроль одинаковых входов:", diff_bits(b"abc", b"abc"))
