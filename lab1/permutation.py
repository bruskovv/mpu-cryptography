from config import config


def _normalize_key(key) -> list[int]:
    if isinstance(key, str):
        key = key.replace(",", " ").split()
    try:
        key = [int(x) for x in key]
    except (TypeError, ValueError):
        raise ValueError("Ключ-перестановка должен состоять из целых чисел")

    n = len(key)
    if n < 2:
        raise ValueError("Ключ-перестановка должен содержать хотя бы 2 элемента")
    if sorted(key) != list(range(1, n + 1)):
        raise ValueError(f"Ключ-перестановка должен содержать числа от 1 до {n} без повторов")
    return key


def _normalize_text(text: str) -> str:
    text = "".join(ch for ch in text.lower() if not ch.isspace())
    if not text:
        raise ValueError("Текст пуст: после удаления пробелов шифровать нечего")
    return text


def _pad_text(text: str, block_size: int) -> str:
    remainder = len(text) % block_size
    if remainder == 0:
        return text
    return text + config.pad_symbol * (block_size - remainder)


def _encrypt_block(block: str, key: list[int]) -> str:
    return "".join(block[key[i] - 1] for i in range(len(key)))


def _decrypt_block(block: str, key: list[int]) -> str:
    restored = [""] * len(key)
    for i, symbol in enumerate(block):
        restored[key[i] - 1] = symbol
    return "".join(restored)


def permutation_enryptor(text: str, key) -> str:
    key = _normalize_key(key)
    block_size = len(key)

    text = _pad_text(_normalize_text(text), block_size)
    encrypted_text = ""

    for start in range(0, len(text), block_size):
        encrypted_text += _encrypt_block(text[start:start + block_size], key)

    return encrypted_text


def permutation_decryptor(text: str, key) -> str:
    key = _normalize_key(key)
    block_size = len(key)

    text = _normalize_text(text)
    if len(text) % block_size != 0:
        raise ValueError(f"Длина шифротекста должна быть кратна длине блока ({block_size})")

    decrypted_text = ""
    for start in range(0, len(text), block_size):
        decrypted_text += _decrypt_block(text[start:start + block_size], key)

    for _ in range(block_size - 1):
        if decrypted_text.endswith(config.pad_symbol):
            decrypted_text = decrypted_text[:-1]
        else:
            break

    return decrypted_text


if __name__ == "__main__":
    print(permutation_enryptor("crypto is good", [3, 1, 4, 2]))              # ycpritsoogdo
    print(permutation_decryptor("ycpritsoogdo", [3, 1, 4, 2]))               # cryptoisgood
    print(permutation_enryptor("attack at dawn", [4, 1, 3, 2]))              # aatttcakndwa
    print(permutation_decryptor("aatttcakndwa", [4, 1, 3, 2]))               # attackatdawn
    print(permutation_enryptor("пришёл увидел победил", "2 5 1 4 3"))        # с заполнителем
    print(permutation_decryptor(
        permutation_enryptor("пришёл увидел победил", "2 5 1 4 3"), "2 5 1 4 3"))
