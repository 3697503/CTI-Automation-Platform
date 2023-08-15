"""
TODO - Parse Procmon CSV
"""

import os
import time
from apscheduler.schedulers.background import BackgroundScheduler, BlockingScheduler
from ioc_finder import find_iocs
import logging
from rich import print
from rich.logging import RichHandler
from pymisp import MISPEvent, MISPAttribute
import base64
import json
import jmespath
import subprocess
import csv
from scapy.all import *
from time import sleep

logging.basicConfig(level=logging.INFO, filename='logwatcher.log', filemode='w')

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
            {
                 'name': 'pestr_log.txt',
                 'status': False
            },
            {
                'name': 'capa_log.json',
                'status': False
            },
            {
                'name': 'capa_log.txt',
                'status': False
            },
            {
                'name': 'pehash_log.json', 
                'status': False
            },
            {
                'name': 'peldd_log.json', 
                'status': False 
            },
            {
                'name': 'pescan_log.json', 
                'status': False
            },
            {
                'name': 'fakenet_log.pcap',
                'status': False
            },
            {
                'name': 'fakenet_log.txt',
                'status': False
            },
            {
                'name': 'autoruns_log.txt',
                'status': False 
            },
            {
                'name': 'autoruns_log.csv',
                'status': False
            },
            {
                'name': 'procmon_log.csv',
                'status': False
            }
        ]
        
        #ioc-type --> misp_ioc_type
        self.misp_type_mappings = {
            'domains': 'domain',
            'urls': 'url',
            'ipv4s': 'ip-dst',
            'email_addresses': 'email',
            'md5s': 'md5',
            'sha1s': 'sha1',
            'sha256s': 'sha256',
            'bitcoin_addresses': 'btc',
        }

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
        enabled_log_names = jmespath.search("[].name", self.enabled_logs)
        try:
            for file in log_files:
                if len([name for name in enabled_log_names if name in file]) == 0:
                    continue
                if 'pestr_log.txt' in file:
                    self.process_pestr(file)
                elif 'capa_log.json' in file:
                    self.process_capa(file)
                elif 'fakenet_log.pcap' in file:
                    self.process_pcap(file)
                elif 'autoruns_log.csv' in file:
                    self.process_autoruns(file)
                
                self.upload_file(file)
                self.set_log_processed(file)
                sleep(3)
        except Exception as e:
            logging.error(e)
            pass

    def set_log_processed(self, logfile_name):
        for log in self.enabled_logs:
            if log['name'] in logfile_name:
                log['status'] = True

    def process_autoruns(self, logfile_name):
        logging.info("Processing {}".format(logfile_name))
        with open('{}/{}'.format(self.LOGS_DIR, logfile_name), 'r', encoding='utf-16') as r_file:
            csvreader = csv.DictReader(r_file)
            for row in csvreader:
                if row['Entry Location'] and row['Entry']:
                    regkey_val = '{}|{}'.format(row['Entry Location'], row['Entry'])
                    attribute = self.convert_to_attribute(regkey_val, 'autoruns', misp_ioc_type='regkey|value')
                    self.misp_event_obj.add_attribute(**attribute)
                    self.misp_client.update_event(self.misp_event_obj)

    def process_capa(self, logfile_name):
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
        try:
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
        except Exception as e:
            logging.error(e)

    def process_pcap(self, pcap_file):
        """
        Extract network observables from a given PCAP and upload them to the MISP event
        """
        packets = rdpcap('{}/{}'.format(self.LOGS_DIR, pcap_file))
        iocs = []
        for packet in packets:
            if packet.haslayer(IP):
                src_ip = packet[IP].src
                iocs.append((src_ip, 'ip-src'))
                dst_ip = packet[IP].dst
                iocs.append((dst_ip, 'ip-dst'))

            if packet.haslayer(DNS):
                for query in packet[DNSQR]:
                    domain = query.qname.decode()
                    iocs.append((domain, 'domain'))

            if packet.haslayer('HTTPRequest'):
                http_request = packet[HTTP]
                if http_request.Method.decode() == "GET":
                    url = http_request.Host.decode() + http_request.Path.decode()
                    iocs.append((url, 'url'))
        for ioc in set(iocs):
            attribute = self.convert_to_attribute(ioc[0], 'fakenet-pcap', misp_ioc_type=ioc[1])
            self.misp_event_obj.add_attribute(**attribute)
            self.misp_client.update_event(self.misp_event_obj)

    def process_pestr(self, logfile_name):
        """
        Run Strings through ioc-finder to detect any IOCs. 
        Convert those IOCs into MISP attributes and attach to the MISP event.
        """
        logging.info("Processing {}".format(logfile_name))
        file_content = self.get_log_file(logfile_name)
        file_content_bytes = file_content.encode("ascii")
        logging.info('Checking for IOCs in PEStr output')
        iocs = find_iocs(file_content)
        for ioc_type in self.misp_type_mappings.keys():
            for ioc in iocs[ioc_type]:
                attribute = self.convert_to_attribute(ioc, 'pestr', ioc_type=ioc_type)
                self.misp_event_obj.add_attribute(**attribute)

        self.upload_file(logfile_name)
        self.misp_event_obj.add_tag(self.sandbox_tag)

        ## Push the updated event to MISP
        self.misp_client.update_event(self.misp_event_obj)

    def process_unstructured(self, logfile_name):
        """
        Run Strings through ioc-finder to detect any IOCs. 
        Convert those IOCs into MISP attributes and attach to the MISP event.
        """
        logging.info("Processing {}".format(logfile_name))
        file_content = self.get_log_file(logfile_name)
        file_content_bytes = file_content.encode("ascii")
        logging.info('Checking for IOCs in {} output'.format(logfile_name))
        iocs = find_iocs(file_content)
        for ioc_type in self.misp_type_mappings.keys():
            for ioc in iocs[ioc_type]:
                attribute = self.convert_to_attribute(misp_type_mappings[ioc_type], ioc, logfile_name.split('_')[0])
                self.misp_event_obj.add_attribute(**attribute)

        self.upload_file(logfile_name)
        self.misp_event_obj.add_tag(self.sandbox_tag)

        ## Push the updated event to MISP
        self.misp_client.update_event(self.misp_event_obj)

    def convert_to_attribute(self, value, analysis_tool, ioc_type=None, misp_ioc_type=None):
        if not ioc_type and not misp_ioc_type:
            raise Exception(('Invalid IOC'))

        logging.info('Converting {} to attribute'.format(value))
        attribute = MISPAttribute(strict=False)
        attribute.value=value
        attribute.type=self.misp_type_mappings[ioc_type] if ioc_type else misp_ioc_type
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

    def request_termination(self):
        logging.info('Termination Requested')
        logs_processed = jmespath.search("[].status", self.enabled_logs)
        while True in logs_processed:
            logging.info('{} has not been processed, delaying termination'.format(file))
            sleep(10)
            logs_processed = jmespath.search("[].status", self.enabled_logs)
        logging.info('Exiting...')
        exit()

    def run(self):
        logging.info("LogWatcher initiated...")
        scheduler = BlockingScheduler() 
        scheduler.add_job(self.check_new_log, 'interval', seconds=5, max_instances=3)
        try:
            logging.info('Cleaning up...')
            subprocess.run(f'rm -rf {self.LOGS_DIR}/*', shell=True)
            self.files = set(os.listdir(self.LOGS_DIR))
            scheduler.start()
        except KeyboardInterrupt:
            logging.info('Cleaning up...')
            subprocess.run(f'rm -rf {self.LOGS_DIR}/*', shell=True)
            exit(0)
