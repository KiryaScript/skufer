import os
import logging
import string
import random
import time
import datetime
import itertools
import binascii

import log_helper
import identity_data

logger = log_helper.setup_logger(name="random_utils", level=logging.INFO, log_to_file=False)


def random_hostname():
    return random.choice(identity_data.HOSTNAMES).strip()


def random_username():
    return random.choice(identity_data.USERNAMES).strip()


def random_mac_address(formatted=True):
    """
    Генерирует MAC-адрес по правилам Locally Administered Address (LAA).
    Второй символ обязан быть 2, 6, A или E. Иначе драйверы Wi-Fi (Intel/Realtek) проигнорируют спуфинг.
    """
    laa_chars = ['2', '6', 'A', 'E']
    first_byte = random.choice(string.hexdigits).upper() + random.choice(laa_chars)
    suffix_bytes = binascii.b2a_hex(os.urandom(5)).decode("utf-8").upper()
    full_hex = first_byte + suffix_bytes

    if formatted:
        return "-".join(full_hex[i:i+2] for i in range(0, 12, 2))
    return full_hex


def random_unix_time(from_date="01.01.2015", to_date="01.01.2024"):
    try:
        from_unix = int(time.mktime(datetime.datetime.strptime(from_date, "%d.%m.%Y").timetuple()))
        to_unix = int(time.mktime(datetime.datetime.strptime(to_date, "%d.%m.%Y").timetuple()))
        return random.randint(from_unix, to_unix)
    except Exception:
        return int(time.time()) - random.randint(86400, 31536000 * 5)


def random_digit_string(length):
    return ''.join(random.choices(string.digits, k=length))


def disperse_string(solid_string):
    normal_list = list(solid_string)
    return list(itertools.chain.from_iterable(zip(normal_list, [0] * len(normal_list))))


def bytes_list_to_array(bytes_list):
    digital_bytes = []
    for elem in bytes_list:
        if isinstance(elem, int):
            digital_bytes.append(elem.to_bytes(1, 'little'))
        elif isinstance(elem, str):
            digital_bytes.append(ord(elem).to_bytes(1, 'little'))
    return b''.join(digital_bytes)


def random_volume_id():
    x1 = binascii.b2a_hex(os.urandom(2)).decode("utf-8").upper()
    x2 = binascii.b2a_hex(os.urandom(2)).decode("utf-8").upper()
    return f"{x1}-{x2}"