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
import json
import jmespath
import subprocess

class LogWatcher():

    def __init__(self, logs_dir, misp_client, misp_event_id):
        # Set the directory to monitor
        self.LOGS_DIR = logs_dir

        # Get the initial set of files in the directory
        self.misp_client = misp_client
        self.misp_event_id = misp_event_id
        misp_event_dict = self.misp_client.get_event(misp_event_id)['Event']
        self.misp_event_obj = MISPEvent()
        self.misp_event_obj.from_dict(**misp_event_dict)
        self.sandbox_tag = 'enriched_via_sandbox'
        self.enabled_logs = [
            'pestr_log.txt',
            'capa_log.json',
            'capa_log.txt',
            'pehash_log.json',
            'peldd_log.json',
            'pescan_log.json',
            'fakenet_log.pcap'
        ]

    def check_new_log(self):
        current_files = set(os.listdir(self.LOGS_DIR))
        current_files = set([file for file in current_files if not file.endswith('.tmp')])
        # logging.debug("Current Files: " + str(current_files))
        new_files = current_files - self.files
        self.files = current_files

        if new_files:
            self.process_logs(new_files)
        # else:
            # logging.info("No new files found")

        # logging.info("Resting for 5 seconds")

    def process_logs(self, log_files):
        logging.info("Processing new logs: " + str(log_files))
        for file in log_files:
            if file not in self.enabled_logs:
                continue
            if file == 'pestr_log.txt':
                self.process_pestr()
            elif file == 'capa_log.json':
                self.process_capa()
            elif file == 'pehash_log.json' or file == 'pescan_log.json' or file == 'capa_log.txt' or file == 'fakenet_log.pcap':
                self.upload_file(file)

    def process_capa(self):
        logfile_name = 'capa_log.json'
        logging.info("Processing {}".format(logfile_name))
        file_content = self.get_log_file(logfile_name)
        capa_dict = json.loads(file_content)
        artifact_md5 = capa_dict['meta']['sample']['md5']
        attribute = self.get_attribute_by_value(artifact_md5)

        attack_tags = []
        for rule_name in capa_dict['rules']:
            attack_dict = capa_dict['rules'][rule_name]['meta']['attack']
            if len(attack_dict) > 0:
                attack_tags.extend(jmespath.search("[].{id: id, technique: technique}", attack_dict))
        if attribute:
            for tag in attack_tags:
                attribute.add_tag("{}: {}".format(tag['id'], tag['technique']))
            attribute.add_tag('capa')
            self.misp_client.update_attribute(attribute)


    def upload_file(self, logfile_name):
        logging.info("Uploading {}".format(logfile_name))
        file_content = None
        with open('{}/{}'.format(self.LOGS_DIR, logfile_name), 'rb') as r_file:
            file_content = r_file.read()
        
        # Upload given file
        self.misp_event_obj.add_attribute(
            'attachment', 
            value=logfile_name,
            data=base64.b64encode(file_content) 
        )
        self.misp_client.update_event(self.misp_event_obj)


    def process_pestr(self):
        """
        Run Strings through ioc-finder to detect any IOCs. 
        Convert those IOCs into MISP attributes and attach to the MISP event.
        """
        logfile_name = 'pestr_log.txt'
        logging.info("Processing {}".format(logfile_name))
        file_content = self.get_log_file(logfile_name)
        file_content_bytes = file_content.encode("ascii")
        logging.info('Checking for IOCs in PEStr output')
        iocs = find_iocs(file_content)
        logging.info(iocs)
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

        # Upload PEStr file
        self.misp_event_obj.add_attribute(
            'attachment', 
            value=logfile_name,
            data=base64.b64encode(file_content_bytes)
        )
        self.misp_event_obj.add_tag(self.sandbox_tag)

        ## Push the updated event to MISP
        self.misp_client.update_event(self.misp_event_obj)

    def convert_to_attribute(self, ioc_type, value, analysis_tool):
        logging.info('Converting {} to attribute'.format(value))
        attribute = MISPAttribute(strict=False)
        attribute.value=value
        attribute.type=ioc_type
        attribute.category= 'Artifacts dropped' if ioc_type in ['md5', 'sha1', 'sha256'] else 'Network activity'
        attribute.comment='Source Tool: {}'.format(analysis_tool)
        attribute.add_tag(analysis_tool)
        attribute.add_tag('suspicious')
        return attribute

    def get_attribute_by_value(self, value):
        # Retrieve the attribute from the search result
        logging.info("Searching for {}".format(value))
        search_result = self.misp_client.search(controller='attributes', value=value)
        if 'Attribute' in search_result:
            for attribute in search_result['Attribute']:
                if attribute['value'] == value:
                    logging.info(f"Attribute ID: {attribute['id']}")
                    attribute_obj = MISPAttribute()
                    attribute_obj.from_dict(**attribute)
                    return attribute_obj
        logging.info("Attribute {} not found.".format_map(value))
        return None

    def get_log_file(self, logfile_name, splitlines=False):
        file_content = None
        try:
            log_file = open(f'{self.LOGS_DIR}/{logfile_name}', 'r', encoding='utf-16')
            file_content = log_file.read()         
        except Exception as e:
            log_file = open(f'{self.LOGS_DIR}/{logfile_name}', 'rb')
            file_content = log_file.read().decode('utf-16')
        log_file.close()
        if file_content == None or len(file_content) == 0:
            raise Exception("No log output")
        
        if splitlines:
                file_content = file_content.splitlines()
        return file_content

    def run(self):
        logging.info("LogWatcher initiated...")
        scheduler = BlockingScheduler() 
        scheduler.add_job(self.check_new_log, 'interval', seconds=5, max_instances=3)
        try:
            # while True:
                # self.check_new_log()
            logging.info('Cleaning up...')
            subprocess.run(f'rm -rf {self.LOGS_DIR}/*', shell=True)
            self.files = set(os.listdir(self.LOGS_DIR))
            scheduler.start()
        except KeyboardInterrupt:
            logging.info('Cleaning up...')
            subprocess.run(f'rm -rf {self.LOGS_DIR}/*', shell=True)
            exit(0)
