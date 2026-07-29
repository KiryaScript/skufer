import os
import sys
import argparse
import logging
import subprocess
import json
import random
import binascii

import log_helper
import system_fingerprint
import hardware_fingerprint
import telemetry_fingerprint
import random_utils
import registry_helper

from registry_helper import RegistryKeyType, Wow64RegistryEntry
from system_utils import is_x64os, platform_version

logger = log_helper.setup_logger(name="antidetect", level=logging.INFO, log_to_file=False)

BACKUP_FILE = "skufer_backup.json"

def safe_write_registry(hive, path, name, type_, new_value, access=Wow64RegistryEntry.KEY_WOW64):
    """Читает старое значение из реестра, сохраняет в бэкап, и записывает новое"""
    old_data = registry_helper.read_value(hive, path, name, access)
    old_val = old_data[0] if old_data else "Not Found"
    reg_type = old_data[1] if old_data else int(type_)
    
    backup_data = {}
    if os.path.exists(BACKUP_FILE):
        try:
            with open(BACKUP_FILE, "r") as f:
                backup_data = json.load(f)
        except Exception:
            pass
            
    full_path = f"{hive}\\{path}\\{name}"
    
    # Сохраняем ТОЛЬКО самое первое (оригинальное) значение
    if full_path not in backup_data and old_val != "Not Found":
        val_to_save = binascii.hexlify(old_val).decode('utf-8') if isinstance(old_val, bytes) else str(old_val)
        backup_data[full_path] = {
            "hive": hive, 
            "path": path, 
            "name": name,
            "value": val_to_save, 
            "type": reg_type
        }
        with open(BACKUP_FILE, "w") as f:
            json.dump(backup_data, f, indent=4)

    registry_helper.write_value(hive, path, name, type_, new_value, access)
    
    display_old = "BINARY DATA" if isinstance(old_val, bytes) else old_val
    display_new = "BINARY DATA" if isinstance(new_value, bytes) else new_value
    return display_old, display_new


def generate_telemetry_fingerprint():
    changes = {}
    windows_ver = platform_version()
    if not ("Windows-10" in windows_ver or "Windows-11" in windows_ver or sys.platform == "win32"):
        return changes

    telemetry_fp = telemetry_fingerprint.TelemetryFingerprint()
    device_id = telemetry_fp.random_device_id_guid()
    device_id_brackets = f"{{{device_id}}}"

    old, new = safe_write_registry("HKEY_LOCAL_MACHINE", r"SOFTWARE\Microsoft\SQMClient", "MachineId", RegistryKeyType.REG_SZ, device_id_brackets)
    changes['Telemetry MachineId'] = {'old': old, 'new': new}

    query_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\SettingsRequests"
    setting_requests = registry_helper.enumerate_key_subkeys("HKEY_LOCAL_MACHINE", query_path)

    if setting_requests:
        for request in setting_requests:
            sub_path = rf"{query_path}\{request}"
            query_params = registry_helper.read_value("HKEY_LOCAL_MACHINE", sub_path, "ETagQueryParameters")
            if query_params and len(query_params) >= 2:
                query_string = str(query_params[0])
                old_device_id = old if (old and old != "Not Found") else None
                
                if old_device_id:
                    new_query_string = query_string.replace(old_device_id, device_id)
                else:
                    new_query_string = query_string
                
                safe_write_registry("HKEY_LOCAL_MACHINE", sub_path, "ETagQueryParameters", RegistryKeyType.REG_SZ, new_query_string)

    return changes


def generate_network_fingerprint():
    changes = {}
    random_host = random_utils.random_hostname()
    random_user = random_utils.random_username()
    hive = "HKEY_LOCAL_MACHINE"
    
    paths = [
        (r"SYSTEM\CurrentControlSet\services\Tcpip\Parameters", "NV Hostname"),
        (r"SYSTEM\CurrentControlSet\services\Tcpip\Parameters", "Hostname"),
        (r"SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName", "ComputerName"),
        (r"SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName", "ComputerName")
    ]
    for path, name in paths:
        old, new = safe_write_registry(hive, path, name, RegistryKeyType.REG_SZ, random_host)
        changes[f"Hostname ({name})"] = {'old': old, 'new': new}

    old, new = safe_write_registry(hive, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "RegisteredOwner", RegistryKeyType.REG_SZ, random_user, Wow64RegistryEntry.KEY_WOW32_64)
    changes["Registered Owner"] = {'old': old, 'new': new}

    # MAC Spoofing только для реальных физических адаптеров
    try:
        new_mac = random_utils.random_mac_address(formatted=False)
        adapters_path = r"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}"
        subkeys = registry_helper.enumerate_key_subkeys(hive, adapters_path)
        
        adapter_changed = False
        for subkey in subkeys:
            if subkey == "Properties": continue
            full_path = f"{adapters_path}\\{subkey}"
            
            driver_desc = registry_helper.read_value(hive, full_path, "DriverDesc")
            characteristics = registry_helper.read_value(hive, full_path, "Characteristics")
            
            # Проверяем, что адаптер является ФИЗИЧЕСКИМ (NCF_PHYSICAL = 0x4)
            is_physical = False
            if characteristics and isinstance(characteristics[0], int):
                if characteristics[0] & 0x4:
                    is_physical = True
            
            # Записываем MAC только если это физическая сетевая карта
            if driver_desc and is_physical:
                old_mac_val = registry_helper.read_value(hive, full_path, "NetworkAddress")
                old_mac = old_mac_val[0] if old_mac_val else "Original"
                safe_write_registry(hive, full_path, "NetworkAddress", RegistryKeyType.REG_SZ, new_mac)
                adapter_changed = True
        
        if adapter_changed:
            changes['MAC Address (Physical)'] = {'old': old_mac, 'new': new_mac}
            
            # Перезапуск ТОЛЬКО физических адаптеров, игнорируя VPN, виртуалки и прочее
            ps_cmd = "Get-NetAdapter | Where-Object {$_.Virtual -eq $False} | Restart-NetAdapter -ErrorAction SilentlyContinue"
            subprocess.run(['powershell', '-NoProfile', '-Command', ps_cmd], capture_output=True)
            changes['Network Adapters'] = {'old': 'Online', 'new': 'Restarted (Physical Only)'}
    except Exception as e:
        logger.error(f"MAC Spoofing error: {e}")

    return changes


def generate_windows_fingerprint():
    changes = {}
    system_fp = system_fingerprint.WinFingerprint()
    hive = "HKEY_LOCAL_MACHINE"
    version_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"

    old, new = safe_write_registry(hive, version_path, "BuildGUID", RegistryKeyType.REG_SZ, system_fp.random_build_guid(), Wow64RegistryEntry.KEY_WOW32_64)
    changes["BuildGUID"] = {'old': old, 'new': new}

    old, new = safe_write_registry(hive, version_path, "BuildLab", RegistryKeyType.REG_SZ, system_fp.random_build_lab(), Wow64RegistryEntry.KEY_WOW32_64)
    changes["BuildLab"] = {'old': old, 'new': new}

    old, new = safe_write_registry(hive, version_path, "CurrentVersion", RegistryKeyType.REG_SZ, system_fp.random_current_version(), Wow64RegistryEntry.KEY_WOW32_64)
    changes["CurrentVersion"] = {'old': old, 'new': new}

    val_dpi = random_utils.bytes_list_to_array(system_fp.random_digital_product_id())
    old, new = safe_write_registry(hive, version_path, "DigitalProductId", RegistryKeyType.REG_BINARY, val_dpi)
    changes["DigitalProductId"] = {'old': old, 'new': new}

    old, new = safe_write_registry(hive, version_path, "ProductId", RegistryKeyType.REG_SZ, system_fp.random_product_id(), Wow64RegistryEntry.KEY_WOW32_64)
    changes["ProductId"] = {'old': old, 'new': new}

    return changes


def generate_hardware_fingerprint():
    changes = {}
    hardware_fp = hardware_fingerprint.HardwareFingerprint()
    hive = "HKEY_LOCAL_MACHINE"

    old, new = safe_write_registry(hive, r"SYSTEM\CurrentControlSet\Control\IDConfigDB\Hardware Profiles\0001", "HwProfileGuid", RegistryKeyType.REG_SZ, hardware_fp.random_hw_profile_guid())
    changes['HwProfileGuid'] = {'old': old, 'new': new}

    old, new = safe_write_registry(hive, r"SOFTWARE\Microsoft\Cryptography", "MachineGuid", RegistryKeyType.REG_SZ, hardware_fp.random_machine_guid())
    changes['MachineGuid'] = {'old': old, 'new': new}

    old, new = safe_write_registry(hive, r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate", "SusClientId", RegistryKeyType.REG_SZ, hardware_fp.random_win_update_guid())
    changes['WinUpdate SusClientId'] = {'old': old, 'new': new}

    # Подмена OEM Данных (Материнская плата)
    oem_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation"
    manufacturers = ["ASUS", "Dell Inc.", "HP", "Lenovo", "Acer", "Micro-Star International Co., Ltd."]
    models = ["System Product Name", "Inspiron", "Pavilion", "ThinkPad", "Predator", "Katana", "AORUS"]
    
    old_m, new_m = safe_write_registry(hive, oem_path, "Manufacturer", RegistryKeyType.REG_SZ, random.choice(manufacturers))
    old_mo, new_mo = safe_write_registry(hive, oem_path, "Model", RegistryKeyType.REG_SZ, random.choice(models))
    changes['OEM Manufacturer'] = {'old': old_m, 'new': new_m}
    changes['OEM Model'] = {'old': old_mo, 'new': new_mo}

    # Запуск внешней утилиты VolumeID
    dir_name = os.path.join(os.path.dirname(__file__), "bin")
    volume_id = random_utils.random_volume_id()
    exe_name = "VolumeID64.exe" if is_x64os() else "VolumeID.exe"
    volume_id_exe = os.path.join(dir_name, exe_name)
    
    if os.path.exists(volume_id_exe):
        try:
            subprocess.run([volume_id_exe, "C:", volume_id], capture_output=True, timeout=5)
            changes['VolumeID C:'] = {'old': 'Unknown', 'new': volume_id}
        except: pass

    return changes


def system_cleanup():
    """Очистка системных следов (Кэш DNS, Темпы, Логи Event Viewer)"""
    changes = {}
    try:
        # 1. DNS & Network Reset
        subprocess.run("ipconfig /flushdns", shell=True, capture_output=True)
        subprocess.run("netsh winsock reset", shell=True, capture_output=True)
        changes["Network/DNS Cache"] = {"old": "Contains traces", "new": "Flushed"}

        # 2. Очистка системных логов событий (Event Viewer)
        subprocess.run('wevtutil el | Foreach-Object {wevtutil cl "$_"}', shell=True, executable="powershell", stderr=subprocess.DEVNULL)
        changes["Windows Event Logs"] = {"old": "Exist", "new": "Cleared"}

        # 3. Очистка Temp файлов
        temp_dirs = [os.environ.get('TEMP'), os.environ.get('TMP'), r"C:\Windows\Temp", r"C:\Windows\Prefetch"]
        for p in temp_dirs:
            if p and os.path.exists(p):
                subprocess.run(f'del /q /f /s "{p}\*"', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        changes["Temp & Prefetch"] = {"old": "Filled", "new": "Cleaned"}

    except Exception as e:
        logger.error(f"Cleanup error: {e}")
    return changes


def restore_backup():
    """Полное восстановление из бэкапа"""
    if not os.path.exists(BACKUP_FILE):
        return {"Backup": {"old": "None", "new": "File Not Found"}}
    
    try:
        with open(BACKUP_FILE, "r") as f:
            data = json.loads(f.read())
    except Exception as e:
        return {"Backup": {"old": "Corrupted", "new": str(e)}}
    
    restored_count = 0
    for path, item in data.items():
        hive, key_path, name, val, vtype = item['hive'], item['path'], item['name'], item['value'], item['type']
        
        if vtype in [RegistryKeyType.REG_BINARY, 3]:  
            try:
                val = binascii.unhexlify(val)
            except: pass
            
        try:
            registry_helper.write_value(hive, key_path, name, vtype, val, Wow64RegistryEntry.KEY_WOW64)
            restored_count += 1
        except: pass
        
    # Сразу после отката перезапускаем физические адаптеры, чтобы вернуть родной MAC
    ps_cmd = "Get-NetAdapter | Where-Object {$_.Virtual -eq $False} | Restart-NetAdapter -ErrorAction SilentlyContinue"
    subprocess.run(['powershell', '-NoProfile', '-Command', ps_cmd], capture_output=True)
        
    return {"Restore Progress": {"old": f"{len(data)} items in backup", "new": f"{restored_count} successfully restored"}}


def run_all(target="ALL"):
    all_changes = {}
    if target in ["ALL", "TELEMETRY"]: all_changes.update(generate_telemetry_fingerprint())
    if target in ["ALL", "NETWORK"]: all_changes.update(generate_network_fingerprint())
    if target in ["ALL", "SYSTEM"]: all_changes.update(generate_windows_fingerprint())
    if target in ["ALL", "HARDWARE"]: all_changes.update(generate_hardware_fingerprint())
    if target == "CLEANUP": all_changes.update(system_cleanup())
    if target == "RESTORE": all_changes.update(restore_backup())
    
    return all_changes

def main():
    run_all("ALL")
    return 0

if __name__ == '__main__':
    sys.exit(main())