import os
import time
from apscheduler.schedulers.background import BackgroundScheduler, BlockingScheduler
from ioc_finder import find_iocs

# Set the directory to monitor
LOGS_DIR = "../win-malware/Analysis_Logs"


ENABLED_LOG_FILES = [
    "capa_log.json",
    "fakenet_log.log",
    "fakenet_log.pcap",
    "pehash_log.json",
    "peldd_log.json",
    "pestr_log.txt"
]

# Get the initial set of files in the directory
files = set(os.listdir(LOGS_DIR))

def check_new_log():
    global files;
    current_files = set(os.listdir(LOGS_DIR))
    print("Curr Files: " + str(current_files))
    new_files = current_files - files

    if new_files:
        print("New Files: " + str(new_files))
        process_logs(new_files)
    else:
        print("No new files found")

    files = current_files
    print("Resting for 5 seconds")

def process_logs(log_files):
    for file in log_files:
        if file == 'pestr_log.txt':
            process_pestr()

def process_pestr():
    print("[+] Processing pestr_log.txt")
    with open(f'{LOGS_DIR}/pestr_log.txt', encoding='utf-16') as r_file: 
        file_content = r_file.read()
        iocs = find_iocs(file_content)
        print(iocs)


def main():
    print("[+] LogWatcher initiated...")
    scheduler = BlockingScheduler() 
    scheduler.add_job(check_new_log, 'interval', seconds=5, max_instances=3)
    try:
        scheduler.start()
    except KeyboardInterrupt:
        pass

main()