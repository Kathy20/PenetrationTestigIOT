###############################################################
#             Instituto Tecnologico de Costa Rica             #
#                  Maestria en Computacion                    #
#                                                             #
#   Estudiante                                                #
#   Kathy Brenes Guerrero                                     #
#                                                             #
#   Fecha                                                     # 
#   Marzo 2021                                                #
###############################################################

import frida
import subprocess
import time
import re
from bs4 import BeautifulSoup
from Common.SaveResult import write_file

# Initialize an empty list to store the results
results = []

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
        results.append(message['payload'])
    elif message['type'] == 'error':
        print(f"[-] Error: {message['stack']}")
        results.append({'error': message['stack']})
    else:
        print(f"[*] {message}")
        results.append(message)

def perform_dynamic_analysis_emulator(app_name):
    try:
        # Attach to the target Android application on the emulator
        session = frida.get_device_manager().add_remote_device(app_name)
        pid = session.spawn([app_name])
        time.sleep(1)  # Wait for the app to start
        session.resume(pid)

        # Load the JavaScript script for dynamic analysis
        with open('android_intercept.js', 'r') as script_file:
            script_content = script_file.read()

        script = session.create_script(script_content)
        script.on('message', on_message)
        script.load()

        # Keep the script running
        input("Press Enter to exit...\n")

        # Detach from the target application
        session.detach()

    except Exception as e:
        print(f"Error: {e}")

def run_spotbugs(java_project_path):
    try:
        subprocess.run(["spotbugs", "-textui", "-effort:max", "-html", "-output", "spotbugs_report.html", java_project_path], check=True)
        print("SpotBugs analysis completed. Check the report in spotbugs_report.html")
    except subprocess.CalledProcessError as e:
        print(f"Error running SpotBugs: {e}")

def look_for_vulnerabilities():
    # Specify the path to the SpotBugs HTML report
    html_report_path = 'spotbugs_report.html'

    # Read the HTML file
    with open(html_report_path, 'r', encoding='utf-8') as html_file:
        soup = BeautifulSoup(html_file, 'html.parser')

    # Find all vulnerability entries in the SpotBugs HTML report
    vulnerabilities = []
    #Find all table rows (<tr>) with the class 'NORMAL', which typically represents vulnerability entries in SpotBugs reports.
    for entry in soup.find_all('tr', class_='NORMAL'):
        # Extract information about each vulnerability
        vulnerability_info = [td.get_text(strip=True) for td in entry.find_all('td')]
        vulnerabilities.append(vulnerability_info)

    # Save the extracted vulnerabilities
    write_file("Cryptography_Static", vulnerabilities)

def perform_static_analysis(apk_path):
    try:
        subprocess.run(["jadx", "-d", "output_directory", apk_path], check=True)
        run_spotbugs(apk_path)
        print("APK decompiled successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error decompiling APK: {e}")

def get_running_apps():
    try:
        # Run 'adb shell dumpsys activity processes' to get information about running processes
        process = subprocess.Popen(['adb', 'shell', 'dumpsys', 'activity', 'processes'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, _ = process.communicate()

        # Extract package names from the output
        package_names = re.findall(r'Proc (\d+): (.+)', output.decode())
        return [package for _, package in package_names]
    except Exception as e:
        print(f"Error: {e}")
        return []

def get_background_apps():
    try:
        # Run 'adb shell dumpsys activity processes' to get information about running processes
        process = subprocess.Popen(['adb', 'shell', 'dumpsys', 'activity', 'processes'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, _ = process.communicate()

        # Extract package names of processes in the background
        background_apps = re.findall(r'(?:Proc|ACTIVITY_MANAGER)(?:.*?)(\b\w+\b)(?:.*?)(?:oom:empty|oom:background)', output.decode())
        return list(set(background_apps))  # Remove duplicates
    except Exception as e:
        print(f"Error: {e}")
        return []
    
def scan_cryptography():
    running_apps = get_running_apps()

    for app in running_apps:
        # Perform dynamic analysis using Frida on the emulator
        perform_dynamic_analysis_emulator(app)

    #Save results from dynamic
    write_file("Cryptography_Dynamic", results)

    background_apps = get_background_apps()
    for app in background_apps:
        # Perform static analysis using JADX
        perform_static_analysis(app)