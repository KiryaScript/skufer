import logging
import log_helper
import enum

try:
    import winreg
except ImportError:
    winreg = None

from system_utils import is_x64os

logger = log_helper.setup_logger(name="registry_helper", level=logging.DEBUG, log_to_file=False)

HIVES_MAP = {}
TYPES_MAP = {}
WOW64_MAP = {}

if winreg is not None:
    HIVES_MAP = {
        "HKEY_CLASSES_ROOT": winreg.HKEY_CLASSES_ROOT,
        "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
        "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
        "HKEY_USERS": winreg.HKEY_USERS,
        "HKEY_PERFORMANCE_DATA": winreg.HKEY_PERFORMANCE_DATA,
        "HKEY_CURRENT_CONFIG": winreg.HKEY_CURRENT_CONFIG,
        "HKEY_DYN_DATA": winreg.HKEY_DYN_DATA
    }


class RegistryKeyType(enum.IntEnum):
    REG_BINARY = 0
    REG_DWORD = 1
    REG_DWORD_LITTLE_ENDIAN = 2
    REG_DWORD_BIG_ENDIAN = 3
    REG_EXPAND_SZ = 4
    REG_LINK = 5
    REG_MULTI_SZ = 6
    REG_NONE = 7
    REG_QWORD = 8
    REG_QWORD_LITTLE_ENDIAN = 9
    REG_RESOURCE_LIST = 10
    REG_FULL_RESOURCE_DESCRIPTOR = 11
    REG_RESOURCE_REQUIREMENTS_LIST = 12
    REG_SZ = 13


if winreg is not None:
    TYPES_MAP = {
        RegistryKeyType.REG_BINARY: winreg.REG_BINARY,
        RegistryKeyType.REG_DWORD: winreg.REG_DWORD,
        RegistryKeyType.REG_DWORD_LITTLE_ENDIAN: winreg.REG_DWORD_LITTLE_ENDIAN,
        RegistryKeyType.REG_DWORD_BIG_ENDIAN: winreg.REG_DWORD_BIG_ENDIAN,
        RegistryKeyType.REG_EXPAND_SZ: winreg.REG_EXPAND_SZ,
        RegistryKeyType.REG_LINK: winreg.REG_LINK,
        RegistryKeyType.REG_MULTI_SZ: winreg.REG_MULTI_SZ,
        RegistryKeyType.REG_NONE: winreg.REG_NONE,
        RegistryKeyType.REG_QWORD: winreg.REG_QWORD,
        RegistryKeyType.REG_QWORD_LITTLE_ENDIAN: winreg.REG_QWORD_LITTLE_ENDIAN,
        RegistryKeyType.REG_RESOURCE_LIST: winreg.REG_RESOURCE_LIST,
        RegistryKeyType.REG_FULL_RESOURCE_DESCRIPTOR: winreg.REG_FULL_RESOURCE_DESCRIPTOR,
        RegistryKeyType.REG_RESOURCE_REQUIREMENTS_LIST: winreg.REG_RESOURCE_REQUIREMENTS_LIST,
        RegistryKeyType.REG_SZ: winreg.REG_SZ
    }


class Wow64RegistryEntry(enum.IntEnum):
    KEY_WOW32 = 0
    KEY_WOW64 = 1
    KEY_WOW32_64 = 2


if winreg is not None:
    WOW64_MAP = {
        Wow64RegistryEntry.KEY_WOW32: winreg.KEY_WOW64_32KEY,
        Wow64RegistryEntry.KEY_WOW64: winreg.KEY_WOW64_64KEY,
        Wow64RegistryEntry.KEY_WOW32_64: 0
    }


def is_key_exist(key_hive, key_path, access_type=Wow64RegistryEntry.KEY_WOW64):
    if winreg is None:
        return False
    if access_type == Wow64RegistryEntry.KEY_WOW32_64:
        access_type = Wow64RegistryEntry.KEY_WOW64

    try:
        key_hive_value = HIVES_MAP[key_hive]
        wow64_flags = WOW64_MAP[access_type]
        key = winreg.OpenKey(key_hive_value, key_path, 0, (wow64_flags | winreg.KEY_READ))
        winreg.CloseKey(key)
        return True
    except Exception:
        return False


def enumerate_key_values(key_hive, key_path, access_type=Wow64RegistryEntry.KEY_WOW64):
    if winreg is None:
        return []
    if access_type == Wow64RegistryEntry.KEY_WOW32_64:
        access_type = Wow64RegistryEntry.KEY_WOW64

    try:
        key_hive_value = HIVES_MAP[key_hive]
        wow64_flags = WOW64_MAP[access_type]
        registry_key = winreg.OpenKey(key_hive_value, key_path, 0, (wow64_flags | winreg.KEY_READ))
        result = []
        for entry_num in range(0, winreg.QueryInfoKey(registry_key)[1]):
            result.append(winreg.EnumValue(registry_key, entry_num))
        winreg.CloseKey(registry_key)
        return result
    except Exception as e:
        logger.debug(f"Unable to enumerate registry key values {key_hive}\\{key_path}: {e}")
        return []


def enumerate_key_subkeys(key_hive, key_path, access_type=Wow64RegistryEntry.KEY_WOW64):
    if winreg is None:
        return []
    if access_type == Wow64RegistryEntry.KEY_WOW32_64:
        access_type = Wow64RegistryEntry.KEY_WOW64

    try:
        key_hive_value = HIVES_MAP[key_hive]
        wow64_flags = WOW64_MAP[access_type]
        registry_key = winreg.OpenKey(key_hive_value, key_path, 0, (wow64_flags | winreg.KEY_READ))
        result = []
        for entry_num in range(0, winreg.QueryInfoKey(registry_key)[0]):
            result.append(winreg.EnumKey(registry_key, entry_num))
        winreg.CloseKey(registry_key)
        return result
    except Exception as e:
        logger.debug(f"Unable to enumerate registry key subkeys {key_hive}\\{key_path}: {e}")
        return []


def create_key(key_hive, key_path, access_type=Wow64RegistryEntry.KEY_WOW64):
    if winreg is None:
        return None
    if access_type == Wow64RegistryEntry.KEY_WOW32_64:
        access_type = Wow64RegistryEntry.KEY_WOW64

    try:
        key_hive_value = HIVES_MAP[key_hive]
        wow64_flags = WOW64_MAP[access_type]
        registry_key = winreg.CreateKeyEx(key_hive_value, key_path, 0, (wow64_flags | winreg.KEY_WRITE))
        return registry_key
    except Exception as e:
        logger.error(f"Unable to create registry key {key_hive}\\{key_path}: {e}")
        return None


def delete_key(key_hive, key_path, access_type=Wow64RegistryEntry.KEY_WOW64):
    if winreg is None:
        return False
    if access_type == Wow64RegistryEntry.KEY_WOW32_64:
        access_type = Wow64RegistryEntry.KEY_WOW64

    try:
        key_hive_value = HIVES_MAP[key_hive]
        wow64_flags = WOW64_MAP[access_type]
        winreg.DeleteKeyEx(key_hive_value, key_path, (wow64_flags | winreg.KEY_WRITE), 0)
        return True
    except Exception as e:
        logger.error(f"Unable to delete registry key {key_hive}\\{key_path}: {e}")
        return False


def create_value(key_hive, key_path, value_name, value_type, key_value, access_type=Wow64RegistryEntry.KEY_WOW64):
    return write_value(key_hive, key_path, value_name, value_type, key_value, access_type)


def delete_value(key_hive, key_path, value_name, access_type=Wow64RegistryEntry.KEY_WOW64):
    if winreg is None:
        return False
    if access_type == Wow64RegistryEntry.KEY_WOW32_64:
        access_type = Wow64RegistryEntry.KEY_WOW64

    try:
        key_hive_value = HIVES_MAP[key_hive]
        wow64_flags = WOW64_MAP[access_type]
        registry_key = winreg.OpenKey(key_hive_value, key_path, 0, (wow64_flags | winreg.KEY_WRITE))
        winreg.DeleteValue(registry_key, value_name)
        winreg.CloseKey(registry_key)
        return True
    except Exception as e:
        logger.error(f"Unable to delete registry value {key_hive}\\{key_path}\\{value_name}: {e}")
        return False


def read_value(key_hive, key_path, value_name, access_type=Wow64RegistryEntry.KEY_WOW64):
    if winreg is None:
        return None

    if is_x64os() and access_type == Wow64RegistryEntry.KEY_WOW32_64:
        v32 = read_value(key_hive, key_path, value_name, Wow64RegistryEntry.KEY_WOW32)
        v64 = read_value(key_hive, key_path, value_name, Wow64RegistryEntry.KEY_WOW64)
        return v32 or v64

    wow64_flags = WOW64_MAP.get(access_type, 0)
    registry_key = None
    try:
        key_hive_value = HIVES_MAP[key_hive]
        registry_key = winreg.OpenKey(key_hive_value, key_path, 0, (wow64_flags | winreg.KEY_READ))
        value, regtype = winreg.QueryValueEx(registry_key, value_name)
        winreg.CloseKey(registry_key)
        return value, regtype
    except Exception as e:
        logger.debug(f"Unable to read from registry path {key_hive}\\{key_path}\\{value_name}: {e}")
        if registry_key is not None:
            try:
                winreg.CloseKey(registry_key)
            except Exception:
                pass
        return None


def write_value(key_hive, key_path, value_name, value_type, key_value, access_type=Wow64RegistryEntry.KEY_WOW64):
    if winreg is None:
        return False

    if is_x64os() and access_type == Wow64RegistryEntry.KEY_WOW32_64:
        res1 = write_value(key_hive, key_path, value_name, value_type, key_value, Wow64RegistryEntry.KEY_WOW32)
        res2 = write_value(key_hive, key_path, value_name, value_type, key_value, Wow64RegistryEntry.KEY_WOW64)
        return res1 or res2

    registry_key = None
    wow64_flags = WOW64_MAP.get(access_type, 0)
    try:
        key_hive_value = HIVES_MAP[key_hive]
        if isinstance(value_type, RegistryKeyType):
            value_type = TYPES_MAP[value_type]

        registry_key = winreg.CreateKeyEx(key_hive_value, key_path, 0, (wow64_flags | winreg.KEY_WRITE))
        winreg.SetValueEx(registry_key, value_name, 0, value_type, key_value)
        winreg.CloseKey(registry_key)
        return True
    except Exception as e:
        logger.error(f"Unable to write to registry path {key_hive}\\{key_path}\\{value_name}: {e}")
        if registry_key is not None:
            try:
                winreg.CloseKey(registry_key)
            except Exception:
                pass
        return False