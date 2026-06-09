import hashlib

class BloomFilter:
    def __init__(self, size: int, num_hashes: int):
        """
        Ініціалізація фільтра Блума.

        :param size: розмір бітового масиву
        :param num_hashes: кількість хеш-функцій
        """
        if not isinstance(size, int) or size <= 0:
            raise ValueError("size має бути додатним цілим числом")

        if not isinstance(num_hashes, int) or num_hashes <= 0:
            raise ValueError("num_hashes має бути додатним цілим числом")

        self.size = size
        self.num_hashes = num_hashes
        self.bit_array = bytearray(size)

    def _hashes(self, item: str):
        """
        Генерує кілька хешів для одного елемента.
        Пароль обробляється як рядок.
        """
        for i in range(self.num_hashes):
            data = f"{item}_{i}".encode("utf-8")
            hash_value = int(hashlib.sha256(data).hexdigest(), 16)
            yield hash_value % self.size

    def add(self, item: str):
        """
        Додає елемент до фільтра Блума.
        """
        if not isinstance(item, str):
            raise TypeError("Пароль має бути рядком")

        if item == "":
            raise ValueError("Пароль не може бути порожнім рядком")

        for index in self._hashes(item):
            self.bit_array[index] = 1

    def contains(self, item: str) -> bool:
        """
        Перевіряє, чи може елемент бути у фільтрі.
        """
        if not isinstance(item, str):
            return False

        if item == "":
            return False

        return all(self.bit_array[index] == 1 for index in self._hashes(item))

    def __contains__(self, item: str) -> bool:
        """
        Дозволяє використовувати синтаксис:
        password in bloom_filter
        """
        return self.contains(item)


def check_password_uniqueness(bloom_filter: BloomFilter, passwords: list) -> dict:
    """
    Перевіряє список паролів на унікальність.

    :param bloom_filter: екземпляр BloomFilter
    :param passwords: список нових паролів
    :return: словник з результатами перевірки
    """
    if not isinstance(bloom_filter, BloomFilter):
        raise TypeError("bloom_filter має бути екземпляром класу BloomFilter")

    if not isinstance(passwords, list):
        raise TypeError("passwords має бути списком")

    results = {}

    for password in passwords:
        if not isinstance(password, str):
            results[str(password)] = "некоректне значення"
            continue

        if password == "":
            results[password] = "некоректне значення"
            continue

        if bloom_filter.contains(password):
            results[password] = "вже використаний"
        else:
            results[password] = "унікальний"
            bloom_filter.add(password)

    return results


if __name__ == "__main__":
    # Ініціалізація фільтра Блума
    bloom = BloomFilter(size=1000, num_hashes=3)

    # Додавання існуючих паролів
    existing_passwords = ["password123", "admin123", "qwerty123"]

    for password in existing_passwords:
        bloom.add(password)

    # Перевірка нових паролів
    new_passwords_to_check = ["password123", "newpassword", "admin123", "guest"]

    results = check_password_uniqueness(bloom, new_passwords_to_check)

    # Виведення результатів
    for password, status in results.items():
        print(f"Пароль '{password}' — {status}.")