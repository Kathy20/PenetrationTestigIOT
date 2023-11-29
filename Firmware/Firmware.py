###############################################################
#             Instituto Tecnologico de Costa Rica             #
#                  Maestria en Computacion                    #
#                                                             #
#   Estudiante                                                #
#   Kathy Brenes Guerrero                                     #
#                                                             #
#   Fecha                                                     # 
#   Marzo 2021                                                #
#   Scan firmware files with JADX and SpotBugs components.    #
###############################################################

import os
import subprocess
import shutil
from bs4 import BeautifulSoup
from Common.SaveResult import write_file

def decompile_apk(apk_path, output_dir):
    try:
        # Use JADX to decompile the APK
        subprocess.run(["jadx", "-d", output_dir, apk_path], check=True)
        print(f"APK decompiled successfully. Output directory: {output_dir}")
    except subprocess.CalledProcessError as e:
        print(f"Error decompiling APK: {e}")

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
    write_file("firmware", vulnerabilities)

def analyze_android_firmware(firmware_path, output_dir):
    # Ensure JADX and SpotBugs are installed
    try:
        subprocess.check_output(["jadx", "--version"])
        subprocess.check_output(["spotbugs", "-version"])
    except subprocess.CalledProcessError:
        print("JADX or SpotBugs is not installed. Please install them.")
        return

    # Create output directory
    os.makedirs(output_dir, exist_ok=True)

    # Extract APK from firmware (assuming it's in a zip file)
    try:
        subprocess.run(["unzip", firmware_path, "-d", output_dir], check=True)
        print("APK extracted successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error extracting APK: {e}")
        return

    # Find and decompile APKs
    for root, dirs, files in os.walk(output_dir):
        for file in files:
            if file.endswith(".apk"):
                apk_path = os.path.join(root, file)
                decompile_output_dir = os.path.join(output_dir, "decompiled", file[:-4])
                decompile_apk(apk_path, decompile_output_dir)

                # Run SpotBugs on the decompiled Java code
                run_spotbugs(decompile_output_dir)

def find_firmware_zip_files(locations):
    firmware_zip_files = []

    for location in locations:
        for foldername, subfolders, filenames in os.walk(location):
            for filename in filenames:
                # Check if the file has a ZIP extension
                if filename.lower().endswith('.zip'):
                    # Get the full path to the ZIP file
                    firmware_zip_path = os.path.join(foldername, filename)
                    firmware_zip_files.append(firmware_zip_path)

    return firmware_zip_files

def pull_boot_partition(output_directory):
    # Use ADB to pull the boot image from the device
    try:
        subprocess.run(["adb", "pull", "/dev/block/bootdevice/by-name/boot", output_directory], check=True)
        print("Boot image successfully pulled.")
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")

def find_location_firmware():
    # Call the function to find firmware ZIP files
    search_location = "firmware_file"
    pull_boot_partition("firmware_file")
    firmware_zip_files = find_firmware_zip_files(search_location)

    # Display the found firmware ZIP files
    if firmware_zip_files:
        print("\nFound firmware ZIP files:")
        for firmware_zip_file in firmware_zip_files:
            print(firmware_zip_file)
    else:
        print("No firmware ZIP files found in the specified locations.")

def local():
    print("Start looking for firmware ...")
    find_location_firmware()

def specific_path():
    user_input = input("Please specify the path: ")
    # Validate the user input
    if os.path.exists(user_input):
        analyze_android_firmware(user_input, ".")
    else:
        print("Invalid directory path. Please enter a valid directory path.")
        scan_firmware()

def exit_menu():
    print("Exiting the menu.")
    exit()

# Define the menu options and associated functions
menu_options = {
    '1': local,
    '2': specific_path,
    '3': exit_menu
}

def scan_firmware():
    print('Is the firmware locally on this device? 1. Yes 2. No')
    print('')

    # Get user input for menu selection
    choice = input("Enter your choice: ").strip().lower()
    # Check if the choice is valid
    if choice in menu_options:
        # Call the selected function
        menu_options[choice]()
    else:
        print("Invalid choice. Please select a valid option.")

if __name__ == "__main__":
    android_firmware_path = "path/to/your/firmware.zip"
    output_directory = "android_firmware_analysis_output"

    analyze_android_firmware(android_firmware_path, output_directory)
