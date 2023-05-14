import os
import time
from apscheduler.schedulers.background import BackgroundScheduler, BlockingScheduler
from ioc_finder import find_iocs
import logging
from rich import print
from rich.logging import RichHandler

logging.basicConfig(level=logging.INFO, handlers=[RichHandler()])

class LogWatcher():

    def __init__(self):
        # Set the directory to monitor
        self.LOGS_DIR = "../win-malware/Analysis_Logs"

        # Get the initial set of files in the directory
        self.files = set(os.listdir(LOGS_DIR))
        self.misp_client = None

    def check_new_log(self):
        current_files = set(os.listdir(LOGS_DIR))
        logging.info("Current Files: " + str(current_files))
        new_files = current_files - files

        if new_files:
            self.process_logs(new_files)
        else:
            logging.info("No new files found")

        self.files = current_files
        logging.info("Resting for 5 seconds")

    def process_logs(self, log_files):
        logging.info("Processing new logs: " + str(log_files))
        for file in log_files:
            if file == 'pestr_log.txt':
                process_pestr()

    def process_pestr(self):
        logging.info("Processing pestr_log.txt")
        with open(f'{LOGS_DIR}/pestr_log.txt', encoding='utf-16') as r_file: 
            file_content = r_file.read()
            iocs = find_iocs(file_content)
            print(iocs)

    def run(self):
        logging.info("LogWatcher initiated...")
        scheduler = BlockingScheduler() 
        scheduler.add_job(check_new_log, 'interval', seconds=5)
        try:
            scheduler.start()
        except KeyboardInterrupt:
            pass