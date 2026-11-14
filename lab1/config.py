class TestConfig:
    def __init__(self):
        self.russian_alphabet = "абвгдеёжзийклмнопрстуфхцчшщъыьэюя"
        self.latin_alphabet = "abcdefghijklmnopqrstuvwxyz"
        # заполнитель для перестановочного шифра (последний неполный блок)
        self.pad_symbol = "~"


config = TestConfig()