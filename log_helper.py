import logging
import sys


def setup_logger(name, level=logging.INFO, log_to_file=False):
    logger = logging.getLogger(name)
    logger.setLevel(level)

    if not logger.handlers:
        console = logging.StreamHandler(sys.stdout)
        console.setLevel(level)
        formatter = logging.Formatter('[%(asctime)s - %(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        console.setFormatter(formatter)
        logger.addHandler(console)
        
        if log_to_file:
            logfile = logging.FileHandler(f'{name}.log', mode='w', encoding='utf-8')
            logfile.setLevel(logging.DEBUG)
            logfile.setFormatter(formatter)
            logger.addHandler(logfile)
            
    return logger