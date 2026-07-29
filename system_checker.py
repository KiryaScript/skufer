import subprocess
import socket
import platform
import csv
import io
import registry_helper

def get_current_mac():
    """Получает MAC-адреса только активных ФИЗИЧЕСКИХ адаптеров через PowerShell."""
    try:
        ps_cmd = "Get-NetAdapter | Where-Object {$_.Virtual -eq $False -and $_.Status -eq 'Up'} | Select-Object Name, MacAddress | ConvertTo-Csv -NoTypeInformation"
        output = subprocess.check_output(['powershell', '-NoProfile', '-Command', ps_cmd], stderr=subprocess.DEVNULL).decode('cp866', errors='ignore').strip()
        
        if not output:
            return "No Active Physical MACs found"
            
        reader = csv.reader(io.StringIO(output))
        macs = []
        for row in reader:
            if len(row) >= 2:
                name = row[0]
                mac = row[1].replace('-', ':') # Приводим к классическому виду
                macs.append(f"{name}: {mac}")
        
        return " | ".join(macs) if macs else "No Active Physical MACs found"
    except Exception:
        return "Unknown"

def get_volume_id():
    """Получает текущий VolumeID диска C:"""
    try:
        output = subprocess.check_output("vol c:", shell=True, text=True, encoding='cp866', stderr=subprocess.DEVNULL)
        return output.strip().split()[-1]
    except Exception:
        return "Unknown"

def get_hardware_components():
    """Получает информацию о CPU, GPU, RAM и Материнской плате."""
    hw_info = {"CPU": "Unknown", "GPU": "Unknown", "RAM": "Unknown", "Motherboard": "Unknown"}
    
    # 1. CPU (Прямое чтение из реестра - самый надежный способ)
    try:
        cpu_val = registry_helper.read_value("HKEY_LOCAL_MACHINE", r"HARDWARE\DESCRIPTION\System\CentralProcessor\0", "ProcessorNameString")
        if cpu_val:
            hw_info["CPU"] = cpu_val[0].strip()
    except Exception:
        pass

    # 2. GPU, RAM и Материнская плата (через PowerShell)
    try:
        ps_cmd = (
            "$gpu = (Get-CimInstance Win32_VideoController | Select-Object -ExpandProperty Name) -join ' & ';"
            "$ram = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB);"
            "$board = (Get-CimInstance Win32_BaseBoard).Product;"
            "Write-Output \"$gpu|||$ram GB|||$board\""
        )
        out_bytes = subprocess.check_output(['powershell', '-NoProfile', '-Command', ps_cmd], stderr=subprocess.DEVNULL)
        parsed = out_bytes.decode('cp866', errors='ignore').strip().split('|||')
        
        if len(parsed) == 3:
            hw_info["GPU"] = parsed[0].strip() if parsed[0].strip() else "Unknown"
            hw_info["RAM"] = parsed[1].strip() if parsed[1].strip() != "0 GB" else "Unknown"
            hw_info["Motherboard"] = parsed[2].strip() if parsed[2].strip() else "Unknown"
    except Exception:
        pass
        
    return hw_info

def get_current_system_info():
    """Собирает текущие показатели из реестра и ОС."""
    info = {}
    
    # --- HARDWARE COMPONENTS ---
    hw = get_hardware_components()
    info['Processor (CPU)'] = hw['CPU']
    info['Graphics (GPU)'] = hw['GPU']
    info['Motherboard'] = hw['Motherboard']
    info['RAM_Size'] = hw['RAM']

    # --- NETWORK ---
    info['Hostname'] = socket.gethostname()
    info['Physical_MACs'] = get_current_mac()

    # --- TELEMETRY ---
    telemetry_id = registry_helper.read_value("HKEY_LOCAL_MACHINE", r"SOFTWARE\Microsoft\SQMClient", "MachineId")
    info['Telemetry_MachineId'] = telemetry_id[0] if telemetry_id else "Not Found"

    # --- SYSTEM ---
    reg_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    build_guid = registry_helper.read_value("HKEY_LOCAL_MACHINE", reg_path, "BuildGUID")
    product_id = registry_helper.read_value("HKEY_LOCAL_MACHINE", reg_path, "ProductId")
    
    info['BuildGUID'] = build_guid[0] if build_guid else "Not Found"
    info['ProductId'] = product_id[0] if product_id else "Not Found"
    info['OS_Version'] = platform.platform()

    # --- HARDWARE ID ---
    hw_guid = registry_helper.read_value("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Control\IDConfigDB\Hardware Profiles\0001", "HwProfileGuid")
    machine_guid = registry_helper.read_value("HKEY_LOCAL_MACHINE", r"SOFTWARE\Microsoft\Cryptography", "MachineGuid")
    
    info['HwProfileGuid'] = hw_guid[0] if hw_guid else "Not Found"
    info['MachineGuid'] = machine_guid[0] if machine_guid else "Not Found"
    info['VolumeID_C'] = get_volume_id()

    return info