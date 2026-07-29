import platform


def is_x64os():
    return platform.machine().endswith('64') or '64' in platform.architecture()[0]


def platform_version():
    return platform.platform()