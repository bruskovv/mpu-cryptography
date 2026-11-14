from config import config


def _get_alphabet(alphabet_name: str) -> str:
    if alphabet_name == "latin":
        return config.latin_alphabet
    return config.russian_alphabet


def _check_key(alphabet_len: int, key: int) -> None:
    if isinstance(key, bool) or not isinstance(key, int):
        raise ValueError("Ключ должен быть целым числом")
    if not 1 <= key <= alphabet_len - 1:
        raise ValueError(f"Ключ должен быть целым от 1 до {alphabet_len - 1}")


def _encrypt_symbol(symbol: str, alphabet_name: str, key: int) -> str:
    alphabet = _get_alphabet(alphabet_name)
    _check_key(len(alphabet), key)
    char_index = (alphabet.find(symbol) + key) % len(alphabet)
    return alphabet[char_index]


def _caesar_convert(text: str, key: int, direction: int) -> str:
    text = text.lower()
    result = ""

    for ch in text:
        if ch in config.latin_alphabet:
            alphabet_name = "latin"
        elif ch in config.russian_alphabet:
            alphabet_name = "russian"
        else:
            result += ch
            continue

        if direction == 1:
            shift = key
        else:
            shift = len(_get_alphabet(alphabet_name)) - key

        result += _encrypt_symbol(ch, alphabet_name, shift)

    return result


def caesar_enryptor(text: str, key: int) -> str:
    return _caesar_convert(text, key, 1)


def caesar_decryptor(text: str, key: int) -> str:
    return _caesar_convert(text, key, -1)


if __name__ == "__main__":
    print(caesar_enryptor("hello", 3))                                   # khoor
    print(caesar_enryptor("яблоко", 3))                                  # вдоснс
    print(caesar_enryptor("Привет, мир! 123", 3))                        # тулезх, плу! 123
    print(caesar_decryptor("khoor", 3))                                  # hello
    print(caesar_decryptor("вдоснс", 3))                                 # яблоко
    print(caesar_decryptor(caesar_enryptor("электрощиток", 7), 7))        # электрощиток

