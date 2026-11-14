from caesar import caesar_decryptor, caesar_enryptor
from permutation import permutation_decryptor, permutation_enryptor
from vigenere import vigenere_decryptor, vigenere_enryptor


def demo(name, text, key, encrypt, decrypt):
    encrypted = encrypt(text, key)
    decrypted = decrypt(encrypted, key)

    print(f"--- {name} ---")
    print("текст       :", text)
    print("ключ        :", key)
    print("шифротекст  :", encrypted)
    print("расшифровка :", decrypted)
    print("D(E(m)) = m :", decrypted == text.lower())  # шифры приводят текст к нижнему регистру
    print()


demo("Цезарь / hello", "hello", 3, caesar_enryptor, caesar_decryptor)
demo("Цезарь / яблоко", "яблоко", 3, caesar_enryptor, caesar_decryptor)
demo("Виженер / криптография", "криптография", "шифр", vigenere_enryptor, vigenere_decryptor)
demo("Виженер / attack at dawn", "attack at dawn", "lemon", vigenere_enryptor, vigenere_decryptor)
demo("Перестановка / cryptoisgood", "cryptoisgood", [3, 1, 4, 2], permutation_enryptor, permutation_decryptor)
demo("Перестановка / attackatdawn", "attackatdawn", [4, 1, 3, 2], permutation_enryptor, permutation_decryptor)
