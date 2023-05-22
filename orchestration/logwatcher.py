"""
TODO - Upload Logs to MISP 
"""

import os
import time
from apscheduler.schedulers.background import BackgroundScheduler, BlockingScheduler
from ioc_finder import find_iocs
import logging
from rich import print
from rich.logging import RichHandler
logging.basicConfig(level=logging.INFO, filename='logwatcher.log', filemode='w')
from pymisp import MISPEvent, MISPAttribute
import base64

class LogWatcher():

    def __init__(self, logs_dir, misp_client, misp_event_id):
        # Set the directory to monitor
        self.LOGS_DIR = logs_dir

        # Get the initial set of files in the directory
        self.files = set(os.listdir(self.LOGS_DIR))
        self.misp_client = misp_client
        self.misp_event_id = misp_event_id
        misp_event_dict = self.misp_client.get_event(misp_event_id)['Event']
        self.misp_event_obj = MISPEvent()
        self.misp_event_obj.from_dict(**misp_event_dict)

    def check_new_log(self):
        current_files = set(os.listdir(self.LOGS_DIR))
        logging.info("Current Files: " + str(current_files))
        new_files = current_files - self.files

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
                self.process_pestr()

    def process_pestr(self):
        logfile_name = 'pestr_log.txt'
        logging.info("Processing {}".format(logfile_name))
        log_file = None
        try:
            log_file = open(f'{self.LOGS_DIR}/{logfile_name}', 'r')
        except Exception as e:
            log_file = open(f'{self.LOGS_DIR}/{logfile_name}', encoding='utf-16')

        file_content = log_file.read()
        file_content_bytes = file_content.encode("ascii")
        log_file.close()
        iocs = find_iocs(file_content)
        misp_type_mappings = {
            'domains': 'domain',
            'urls': 'url',
            'ipv4s': 'ip-dst',
            'email_addresses': 'email',
            'md5s': 'md5',
            'sha1s': 'sha1',
            'sha256s': 'sha256',
            'bitcoin_addresses': 'btc'
        }
        for ioc_type in misp_type_mappings.keys():
            for ioc in iocs[ioc_type]:
                attribute = self.convert_to_attribute(misp_type_mappings[ioc_type], ioc, 'pestr')
                self.misp_event_obj.add_attribute(**attribute)

        self.misp_event_obj.add_attribute(
            'attachment', 
            value=logfile_name,
            data=base64.b64encode(file_content_bytes) 
        )
        self.misp_event_obj.add_tag('enriched_via_sandbox')

        ## Push the updated event to MISP
        event_dict = self.misp_client.update_event(self.misp_event_obj)

    def convert_to_attribute(self, ioc_type, value, analysis_tool):
        print('Converting {} of type {}'.format(value, ioc_type))
        attribute = MISPAttribute(strict=False)
        attribute.value=value
        attribute.type=ioc_type
        attribute.category= 'Artifacts dropped' if ioc_type in ['md5', 'sha1', 'sha256'] else 'Network activity'
        attribute.comment='Source Tool: {}'.format(analysis_tool)
        attribute.add_tag(analysis_tool)
        attribute.add_tag('suspicious')
        return attribute

    def run(self):
        logging.info("LogWatcher initiated...")
        scheduler = BlockingScheduler() 
        scheduler.add_job(self.check_new_log, 'interval', seconds=5)
        try:
            scheduler.start()
        except KeyboardInterrupt:
            pass