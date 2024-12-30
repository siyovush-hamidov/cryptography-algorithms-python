import struct

class Sha_1:
    # Инициализационные переменные
    H0 = 0x67452301
    H1 = 0xEFCDAB89
    H2 = 0x98BADCFE
    H3 = 0x10325476
    H4 = 0xC3D2E1F0

    @staticmethod
    def _left_rotate(n, b):
        """Циклический сдвиг налево""" 
        return ((n << b) | (n >> (32 - b))) & 0xffffffff

    @staticmethod
    def sha_1(data):
        """Реализация SHA-1"""
        # Использование локальных переменных
        H0 = Sha_1.H0
        H1 = Sha_1.H1
        H2 = Sha_1.H2
        H3 = Sha_1.H3
        H4 = Sha_1.H4

        # Предварительная обработка
        original_byte_len = len(data)
        original_bit_len = original_byte_len * 8

        # Добавление 1 бит и 0 битов до 448 (мод 512)
        data += b'\x80'
        data += b'\x00' * ((56 - len(data) % 64) % 64)

        # Добавление длины исходного сообщения
        data += struct.pack('>Q', original_bit_len)

        # Обработка каждого 512-битного блока
        for i in range(0, len(data), 64):
            w = [0] * 80
            for j in range(16):
                w[j] = struct.unpack('>I', data[i + j * 4:i + j * 4 + 4])[0]
            for j in range(16, 80):
                w[j] = Sha_1._left_rotate(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1)

            # Инициализация временных переменных
            a = H0
            b = H1
            c = H2
            d = H3
            e = H4

            # Основной цикл
            for j in range(80):
                if 0 <= j <= 19:
                    f = (b & c) | ((~b) & d)
                    k = 0x5A827999
                elif 20 <= j <= 39:
                    f = b ^ c ^ d
                    k = 0x6ED9EBA1
                elif 40 <= j <= 59:
                    f = (b & c) | (b & d) | (c & d)
                    k = 0x8F1BBCDC
                elif 60 <= j <= 79:
                    f = b ^ c ^ d
                    k = 0xCA62C1D6

                temp = (Sha_1._left_rotate(a, 5) + f + e + k + w[j]) & 0xffffffff
                e = d
                d = c
                c = Sha_1._left_rotate(b, 30)
                b = a
                a = temp

            # Добавление временных переменных к инициализационным
            H0 = (H0 + a) & 0xffffffff
            H1 = (H1 + b) & 0xffffffff
            H2 = (H2 + c) & 0xffffffff
            H3 = (H3 + d) & 0xffffffff
            H4 = (H4 + e) & 0xffffffff

        # Возвращение итогового хеша
        return f"{H0:08x}{H1:08x}{H2:08x}{H3:08x}{H4:08x}"
# Пример использования
#input_string = "Привет"
#print(f"SHA-1 хеш: {Sha_1.sha_1(input_string.encode())}")
