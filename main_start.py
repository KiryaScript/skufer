import os
import time
import sys
import ctypes
from colorama import init, Fore, Style

import system_checker
import generate_fingerprint

init(autoreset=True)


def is_admin():
    """Проверка, запущен ли скрипт с правами администратора"""
    try:
        if os.name == 'nt':
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception:
        return False


def check_admin():
    """Проверка прав администратора и завершение работы, если не админ"""
    if not is_admin():
        print(Fore.RED + "[!] ВНИМАНИЕ: Скрипт запущен без прав администратора!")
        print(Fore.YELLOW + "[!] Спуфинг реестра и MAC-адреса не сработает. Перезапустите от имени Администратора.")
        input("\nНажмите Enter для выхода...")
        sys.exit(1)


def print_banner():
    os.system("cls" if os.name == "nt" else "clear")
    banner = f"""{Fore.CYAN}
╔══════════════════════════════════════════════════════════════╗
║   ███████╗██╗  ██╗██╗   ██╗███████╗███████╗██████╗           ║
║   ██╔════╝██║ ██╔╝██║   ██║██╔════╝██╔════╝██╔══██╗          ║
║   ███████╗█████╔╝ ██║   ██║█████╗  █████╗  ██████╔╝          ║
║   ╚════██║██╔═██╗ ██║   ██║██╔══╝  ██╔══╝  ██╔══██╗          ║
║   ███████║██║  ██╗╚██████╔╝██║     ███████╗██║  ██║          ║
║   ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═╝          ║
║               {Fore.RED}SAFE YOUR ASS by. devik{Fore.CYAN}                   ║
╚══════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}"""
    print(banner)


def show_current_info():
    print(f"\n{Fore.YELLOW}[*] Сканирование текущих идентификаторов системы...{Style.RESET_ALL}\n")
    info = system_checker.get_current_system_info()
    
    print(f"{Fore.WHITE}{'ПАРАМЕТР':<25} | {'ЗНАЧЕНИЕ'}")
    print("-" * 90)
    for key, val in info.items():
        if val == "Not Found" or val == "Unknown":
            color = Fore.RED
        else:
            color = Fore.GREEN
            
        if key == "Physical_MACs":
            macs = val.split(" | ")
            print(f"{Fore.CYAN}{key:<25}{Style.RESET_ALL} | {color}{macs[0]}{Style.RESET_ALL}")
            for m in macs[1:]:
                print(f"{'':<25} | {color}{m}{Style.RESET_ALL}")
        else:
            print(f"{Fore.CYAN}{key:<25}{Style.RESET_ALL} | {color}{val}{Style.RESET_ALL}")
    
    input(f"\n{Fore.YELLOW}Нажмите Enter для возврата в меню...{Style.RESET_ALL}")


def print_changes_table(changes_dict):
    print(f"\n{Fore.GREEN}[+] ОТЧЕТ ОБ ИЗМЕНЕНИЯХ:{Style.RESET_ALL}\n")
    print(f"{Fore.WHITE}{'ПАРАМЕТР':<25} | {'СТАРОЕ ЗНАЧЕНИЕ':<35} | {'НОВОЕ ЗНАЧЕНИЕ':<35}")
    print("-" * 100)
    for key, data in changes_dict.items():
        old_v = str(data['old'])[:33]
        new_v = str(data['new'])[:33]
        print(f"{Fore.CYAN}{key:<25}{Style.RESET_ALL} | {Fore.RED}{old_v:<35}{Style.RESET_ALL} | {Fore.GREEN}{new_v:<35}{Style.RESET_ALL}")


def run_spoofer(target):
    print(f"\n{Fore.YELLOW}[*] Выполняется задача: {target}... Это может занять несколько секунд.{Style.RESET_ALL}")
    
    try:
        changes = generate_fingerprint.run_all(target)
        if changes:
            print_changes_table(changes)
            if target not in ["RESTORE", "CLEANUP"]:
                print(f"\n{Fore.GREEN}[✔] ВНИМАНИЕ: Бэкап оригинальных значений сохранен в файл skufer_backup.json{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.RED}[!] Изменения не были применены или возникла ошибка.{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}[X] Критическая ошибка выполнения: {e}{Style.RESET_ALL}")

    input(f"\n{Fore.YELLOW}Нажмите Enter для возврата в меню...{Style.RESET_ALL}")


def menu():
    while True:
        print_banner()
        print(f"{Fore.WHITE}Выберите действие:{Style.RESET_ALL}")
        print(f" {Fore.MAGENTA}[1]{Style.RESET_ALL} Посмотреть ТЕКУЩИЕ данные системы {Fore.GREEN}(Все MAC, CPU, GPU и HWID){Style.RESET_ALL}")
        print(f" {Fore.CYAN}[2]{Style.RESET_ALL} Изменить Telemetry (MachineId, DiagTrack)")
        print(f" {Fore.CYAN}[3]{Style.RESET_ALL} Изменить Network   (Hostname, Пользователь, LAA MAC физических карт)")
        print(f" {Fore.CYAN}[4]{Style.RESET_ALL} Изменить System    (Build GUID, ProductId, Edition, OS Version)")
        print(f" {Fore.CYAN}[5]{Style.RESET_ALL} Изменить Hardware  (HWID, MachineGuid, OEM, VolumeID)")
        print(f" {Fore.RED}[6] ПРИМЕНИТЬ ВСЕ СПУФЕРЫ СРАЗУ{Style.RESET_ALL}")
        print(f" {Fore.YELLOW}[7] Очистка следов     (Очистка DNS, Temp, Prefetch, Event Logs){Style.RESET_ALL}")
        print(f" {Fore.YELLOW}[8] ОТКАТ К ОРИГИНАЛУ  (Восстановить реестр и реальные MAC из бэкапа){Style.RESET_ALL}")
        print(f" {Fore.WHITE}[0]{Style.RESET_ALL} Выход")
        
        choice = input(f"\n{Fore.YELLOW}Ваш выбор: > {Style.RESET_ALL}")
        
        if choice == "1":
            show_current_info()
        elif choice == "2":
            run_spoofer("TELEMETRY")
        elif choice == "3":
            run_spoofer("NETWORK")
        elif choice == "4":
            run_spoofer("SYSTEM")
        elif choice == "5":
            run_spoofer("HARDWARE")
        elif choice == "6":
            print(f"\n{Fore.RED}[!] ВНИМАНИЕ! Рекомендуется закрыть другие программы.{Style.RESET_ALL}")
            print(f"{Fore.RED}[!] При смене сети (MAC) у вас на пару секунд пропадет интернет.{Style.RESET_ALL}")
            confirm = input("Продолжить? (y/n): ")
            if confirm.lower() == 'y':
                run_spoofer("ALL")
        elif choice == "7":
            run_spoofer("CLEANUP")
        elif choice == "8":
            print(f"\n{Fore.RED}[!] ВНИМАНИЕ! Это действие отменит все предыдущие спуфы (вернет заводские HWID).{Style.RESET_ALL}")
            confirm = input("Восстановить систему? (y/n): ")
            if confirm.lower() == 'y':
                run_spoofer("RESTORE")
        elif choice == "0":
            print(f"\n{Fore.CYAN}[*] Завершение работы SKUFER...{Style.RESET_ALL}")
            break
        else:
            print(f"{Fore.RED}Неверный выбор!{Style.RESET_ALL}")
            time.sleep(1)


if __name__ == '__main__':
    check_admin()
    menu()