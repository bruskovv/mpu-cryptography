from config import config
from feistel import derive_master_key, encrypt_bytes


def diff_bits(first: bytes, second: bytes) -> int:
    """Сколько битов различается в двух одинаковых по длине наборах байт."""
    if len(first) != len(second):
        raise ValueError("Сравнивать можно только данные одинаковой длины")
    return bin(int.from_bytes(first, "big") ^ int.from_bytes(second, "big")).count("1")


def flip_bit(data: bytes, bit_index: int) -> bytes:
    """Инвертировать один бит; нумерация битов идёт слева направо с нуля."""
    if not 0 <= bit_index < len(data) * 8:
        raise ValueError(f"Номер бита должен быть от 0 до {len(data) * 8 - 1}")
    byte_index, bit_in_byte = divmod(bit_index, 8)
    flipped = data[byte_index] ^ (1 << (7 - bit_in_byte))
    return data[:byte_index] + bytes([flipped]) + data[byte_index + 1:]


def _first_block_diff(first: bytes, second: bytes) -> int:
    """Отличия только в первом шифроблоке.

    Текст всегда добивается до целого числа блоков, поэтому в шифротексте
    есть ещё блок дополнения. Он не менялся, если меняли бит текста, и
    сравнение «всего» тогда занижает результат ровно вдвое.
    """
    return diff_bits(first[:config.block_bytes], second[:config.block_bytes])


def avalanche_text(text: str, key: str, bit_index: int) -> tuple[str, str, int]:
    """Изменить один бит текста: вернуть оба шифротекста и число различий."""
    master = derive_master_key(key)
    original = text.encode("utf-8")
    changed = flip_bit(original, bit_index)
    first = encrypt_bytes(original, master)
    second = encrypt_bytes(changed, master)
    return first.hex(), second.hex(), _first_block_diff(first, second)


def avalanche_key(text: str, key: str, bit_index: int) -> tuple[str, str, int]:
    """Изменить один бит свёрнутого ключа: вернуть шифротексты и различия."""
    if not 0 <= bit_index < config.block_bits:
        raise ValueError(f"Номер бита ключа должен быть от 0 до {config.block_bits - 1}")

    data = text.encode("utf-8")
    master = derive_master_key(key)
    changed_master = master ^ (1 << (config.block_bits - 1 - bit_index))
    first = encrypt_bytes(data, master)
    second = encrypt_bytes(data, changed_master)
    return first.hex(), second.hex(), _first_block_diff(first, second)


def _rows(text: str, key: str, bits: int, function) -> list[tuple[int, str, str, int]]:
    rows = []
    for bit_index in range(bits):
        first, second, difference = function(text, key, bit_index)
        rows.append((bit_index, first, second, difference))
    return rows


def text_avalanche_table(text: str, key: str) -> list[tuple[int, str, str, int]]:
    """По одной строке на каждый бит текста."""
    return _rows(text, key, len(text.encode("utf-8")) * 8, avalanche_text)


def key_avalanche_table(text: str, key: str) -> list[tuple[int, str, str, int]]:
    """По одной строке на каждый бит ключа."""
    return _rows(text, key, config.block_bits, avalanche_key)


def summarize(rows: list[tuple[int, str, str, int]]) -> dict:
    values = [row[3] for row in rows]
    block_bits = config.block_bytes * 8
    return {
        "count": len(values),
        "block_bits": block_bits,
        "minimum": min(values),
        "maximum": max(values),
        "average": round(sum(values) / len(values), 2),
        "percent": round(sum(values) / len(values) / block_bits * 100, 1),
    }


def rounds_experiment(text: str, key: str, rounds_list: list[int]) -> list[tuple[int, float, float]]:
    """Среднее число отличающихся битов в зависимости от числа раундов."""
    saved_rounds = config.rounds
    result = []
    try:
        for rounds in rounds_list:
            config.rounds = rounds
            text_summary = summarize(text_avalanche_table(text, key))
            key_summary = summarize(key_avalanche_table(text, key))
            result.append((rounds, text_summary["average"], key_summary["average"]))
    finally:
        config.rounds = saved_rounds
    return result


if __name__ == "__main__":
    for name, rows in (
        ("бит текста", text_avalanche_table("Hi", "secret")),
        ("бит ключа", key_avalanche_table("Hi", "secret")),
    ):
        print(f"--- изменяем {name} ---")
        for bit_index, first, second, difference in rows:
            print(f"{bit_index:2}  {first}  {second}  {difference}")
        print("сводка:", summarize(rows))

    print()
    print("--- зависимость от числа раундов ---")
    for rounds, text_average, key_average in rounds_experiment("Hi", "secret", [4, 6, 8, 12, 16]):
        print(f"раундов {rounds:2}: текст {text_average}, ключ {key_average}")
