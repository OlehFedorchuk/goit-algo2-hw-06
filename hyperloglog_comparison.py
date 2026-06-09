import json
import time
import hashlib
import ipaddress
import math
from typing import Iterator

LOG_FILE = "lms-stage-access.log"

def is_valid_ip(value: str) -> bool:
    """
    Перевіряє, чи є значення коректною IP-адресою.
    """
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

def load_ip_addresses(file_path: str) -> Iterator[str]:
    """
    Завантажує IP-адреси з лог-файлу.
    """
    with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            line = line.strip()

            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            ip = record.get("remote_addr")

            if isinstance(ip, str) and is_valid_ip(ip):
                yield ip


class HyperLogLog:

    def __init__(self, p: int = 14):
        if not 4 <= p <= 16:
            raise ValueError("p must be between 4 and 16")

        self.p = p
        self.m = 1 << p
        self.registers = [0] * self.m
        self.alpha = self._get_alpha()

    def _get_alpha(self) -> float:
        if self.m == 16:
            return 0.673
        if self.m == 32:
            return 0.697
        if self.m == 64:
            return 0.709

        return 0.7213 / (1 + 1.079 / self.m)

    @staticmethod
    def _hash(value: str) -> int:
        """
        Перетворює IP-адресу у 64-бітне число.
        """
        digest = hashlib.sha1(value.encode("utf-8")).digest()
        return int.from_bytes(digest[:8], byteorder="big")

    @staticmethod
    def _leading_zeros(x: int, bits: int) -> int:
        """
        Рахує кількість нулів на початку бінарного числа.
        """
        if x == 0:
            return bits

        return bits - x.bit_length()

    def add(self, value: str) -> None:
        """
        Додає елемент у HyperLogLog.
        """
        x = self._hash(value)

        # Перші p бітів вибирають номер регістра
        index = x >> (64 - self.p)

        # Решта бітів використовуються для підрахунку нулів
        remaining_bits = x & ((1 << (64 - self.p)) - 1)

        rank = self._leading_zeros(remaining_bits, 64 - self.p) + 1

        self.registers[index] = max(self.registers[index], rank)

    def count(self) -> float:
        """
        Повертає приблизну кількість унікальних елементів.
        """
        raw_estimate = self.alpha * (self.m ** 2) / sum(
            2.0 ** (-register) for register in self.registers
        )

        # Корекція для малих значень
        empty_registers = self.registers.count(0)

        if raw_estimate <= 2.5 * self.m and empty_registers > 0:
            return self.m * math.log(self.m / empty_registers)

        return raw_estimate


def exact_count(file_path: str) -> int:
    """
    Точний підрахунок унікальних IP-адрес через set.
    """
    unique_ips = set()

    for ip in load_ip_addresses(file_path):
        unique_ips.add(ip)

    return len(unique_ips)


def hll_count(file_path: str, p: int = 14) -> int:
    """
    Наближений підрахунок унікальних IP-адрес через HyperLogLog.
    """
    hll = HyperLogLog(p=p)

    for ip in load_ip_addresses(file_path):
        hll.add(ip)

    return round(hll.count())


def benchmark(func, *args):
    """
    Вимірює час виконання функції.
    """
    start = time.perf_counter()
    result = func(*args)
    elapsed_time = time.perf_counter() - start

    return result, elapsed_time


def print_results(
    exact_result: int,
    exact_time: float,
    hll_result: int,
    hll_time: float,
) -> None:
    """
    Виводить результати у вигляді таблиці.
    """
    print("Результати порівняння:")
    print(f"{'':<28}{'Точний підрахунок':>20}{'HyperLogLog':>15}")
    print(
        f"{'Унікальні елементи':<28}"
        f"{float(exact_result):>20.1f}"
        f"{float(hll_result):>15.1f}"
    )
    print(
        f"{'Час виконання (сек.)':<28}"
        f"{exact_time:>20.6f}"
        f"{hll_time:>15.6f}"
    )

    if exact_result > 0:
        error = abs(hll_result - exact_result) / exact_result * 100
    else:
        error = 0

def main() -> None:
    exact_result, exact_time = benchmark(exact_count, LOG_FILE)
    hll_result, hll_time = benchmark(hll_count, LOG_FILE, 14)

    print_results(exact_result, exact_time, hll_result, hll_time)


if __name__ == "__main__":
    main()