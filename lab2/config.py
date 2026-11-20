class LabConfig:
    def __init__(self):
        # блок 16 бит = две половины по 8 бит (требование методички)
        self.block_bits = 16
        self.block_bytes = self.block_bits // 8
        self.half_bits = self.block_bits // 2

        # раундов не меньше четырёх; берём 8, чтобы эффект был заметнее
        self.rounds = 8

        # сдвиг внутри функции F (циклический, влево)
        self.f_shift = 3

        # константа, разводящая подключи разных раундов
        self.subkey_step = 0x1D

        # нечётный множитель для перемешивания битов мастера при выработке подключей
        self.master_mix = 0x1F

        # сдвиг при свёртке ключа-строки в 16-битное значение
        self.key_shift = 3


config = LabConfig()
