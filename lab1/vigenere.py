from config import config


def _get_alphabet(alphabet_name: str) -> str:
    if alphabet_name == "latin":
        return config.latin_alphabet
    return config.russian_alphabet


def _normalize_key(key: str) -> str:
    if not isinstance(key, str):
        raise ValueError("Ключ должен быть непустой строкой")
    key = key.lower().replace(" ", "")
    if not key:
        raise ValueError("Ключ должен быть непустой строкой")
    return key


def _check_alphabet_and_encrypt_char(alphabet_name: str, ch: str, key: str,
                                    letter_index: int, direction: int = 1) -> str:
    alphabet = _get_alphabet(alphabet_name)
    alphabet_len = len(alphabet)

    char_alphabet_index = alphabet.find(ch)
    key_symbol = key[letter_index % len(key)]
    if key_symbol not in alphabet:
        raise ValueError("Символ ключа не совпадает с алфавитом символа, на который используется")
    key_alphabet_index = alphabet.find(key_symbol)

    return alphabet[(char_alphabet_index + direction * key_alphabet_index) % alphabet_len]


def _vigenere_convert(text: str, key: str, direction: int) -> str:
    key = _normalize_key(key)
    text = text.lower()

    result = ""
    letter_index = 0

    for ch in text:
        if ch in config.latin_alphabet:
            alphabet_name = "latin"
        elif ch in config.russian_alphabet:
            alphabet_name = "russian"
        else:
            result += ch
            continue

        result += _check_alphabet_and_encrypt_char(
            alphabet_name, ch, key, letter_index, direction
        )
        letter_index += 1
    return result


def vigenere_enryptor(text: str, key: str) -> str:
    return _vigenere_convert(text, key, 1)


def vigenere_decryptor(text: str, key: str) -> str:
    return _vigenere_convert(text, key, -1)


if __name__ == "__main__":
    print(vigenere_enryptor("криптография", "шифр"))          # гщэакччбшээп
    print(vigenere_decryptor("гщэакччбшээп", "шифр"))        # криптография
    print(vigenere_enryptor("attack at dawn", "lemon"))       # lxfopv ef rnhr
    print(vigenere_enryptor("attackatdawn", "lemon"))         # lxfopvefrnhr
    print(vigenere_decryptor(vigenere_enryptor("Защита информации 2026!", "ключ"), "ключ"))
