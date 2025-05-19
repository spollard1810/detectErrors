import netmiko
import os
import time
import pandas as pd
from dataclasses import dataclass
from typing import Optional, Dict, Any
from netmiko import ConnectHandler, SSHDetect
from datetime import datetime
from ntc_templates.parse import parse_output
import threading
import csv

@dataclass
class Device:
    ip: str
    username: str
    password: str
    device_type: Optional[str] = None
    hostname: Optional[str] = None
    interfaces: Optional[Dict[str, Any]] = None

def detect_device(device: Device):
    try:
        #using SSHDetect to detect the device type, defaulting to cisco_ios if no device type is detected - also XE -> cisco_ios
        device_type = SSHDetect(ip=device.ip, username=device.username, password=device.password)
        device_type = device_type.autodetect()
        if device_type == 'cisco_xe':
            device_type = 'cisco_ios'
        device.device_type = device_type
    except Exception as e:
        print(f"Error detecting device type for {device.ip}: {e}")
        device.device_type = 'cisco_ios'
    return device

def connect_to_device(device: Device) -> ConnectHandler:
    try:
        return ConnectHandler(
            ip=device.ip,
            username=device.username,
            password=device.password,
            device_type=device.device_type
        )
    except Exception as e:
        print(f"Error connecting to {device.ip}: {e}")
        raise

def get_device_facts(device: Device, connection: ConnectHandler):
    try:
        # Get hostname
        hostname_output = connection.send_command('show run | i hostname')
        device.hostname = hostname_output.split('hostname ')[-1].strip()
        
        # Get interface information
        interface_output = connection.send_command('show interfaces')
        parsed_interfaces = parse_output(platform=device.device_type, command='show interfaces', data=interface_output)
        device.interfaces = sort_interfaces(parsed_interfaces)
        
        return device
    except Exception as e:
        print(f"Error getting facts for {device.ip}: {e}")
        raise

def sort_interfaces(interfaces: dict):
    # Filter interfaces to only include those with common error counters
    filtered_interfaces = {}
    for interface, data in interfaces.items():
        # Check for common error counters
        has_errors = False
        
        # Common error counters to check
        error_counters = {
            'crc': data.get('crc', 0),
            'input_errors': data.get('input_errors', 0),
            'output_errors': data.get('output_errors', 0),
            'input_drops': data.get('input_drops', 0),
            'output_drops': data.get('output_drops', 0),
            'input_collisions': data.get('input_collisions', 0),
            'output_collisions': data.get('output_collisions', 0),
            'late_collisions': data.get('late_collisions', 0),
            'deferred': data.get('deferred', 0),
            'giants': data.get('giants', 0),
            'runts': data.get('runts', 0),
            'ignored': data.get('ignored', 0),
            'overrun': data.get('overrun', 0),
            'abort': data.get('abort', 0),
            'resets': data.get('resets', 0)
        }
        
        # Check if any error counter is >= 1
        for counter, value in error_counters.items():
            if value >= 1:
                has_errors = True
                break
        
        if has_errors:
            filtered_interfaces[interface] = data
    
    return filtered_interfaces

def prepare_dataframe(devices: list[Device]) -> pd.DataFrame:
    rows = []
    for device in devices:
        if device.interfaces:
            for interface, data in device.interfaces.items():
                row = {
                    'hostname': device.hostname,
                    'ip': device.ip,
                    'interface': interface,
                    **data
                }
                rows.append(row)
    return pd.DataFrame(rows)

def save_data(df: pd.DataFrame):
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'interface_errors_{timestamp}.csv'
    df.to_csv(filename, index=False)
    print(f"Data saved to {filename}")

def get_creds():
    #get the credentials from the user
    username = input("Enter the username: ")
    password = input("Enter the password: ")
    return username, password

def load_devices():
    devices = []
    username, password = get_creds()
    #creating list of devices from devices.csv and prompting user for credentials
    with open('devices.csv', 'r') as file:
        reader = csv.reader(file)
        for row in reader:
            device = Device(ip=row[0], username=username, password=password)
            devices.append(device)
    return devices

def worker(device: Device):
    try:
        # Step 1: Detect device type
        device = detect_device(device)
        
        # Step 2: Connect to device
        connection = connect_to_device(device)
        
        # Step 3: Get device facts
        device = get_device_facts(device, connection)
        
        # Step 4: Close connection
        connection.disconnect()
        
        return device
    except Exception as e:
        print(f"Error processing device {device.ip}: {e}")
        return None
    
def toSortableHTML(df: pd.DataFrame):
    # Add CSS and JavaScript for sorting
    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Interface Error Report</title>
        <style>
            table {
                border-collapse: collapse;
                width: 100%;
                margin: 20px 0;
                font-family: Arial, sans-serif;
            }
            th, td {
                border: 1px solid #ddd;
                padding: 8px;
                text-align: left;
            }
            th {
                background-color: #4CAF50;
                color: white;
                cursor: pointer;
            }
            tr:nth-child(even) {
                background-color: #f2f2f2;
            }
            tr:hover {
                background-color: #ddd;
            }
            .error {
                color: red;
                font-weight: bold;
            }
        </style>
        <script>
            function sortTable(n) {
                var table, rows, switching, i, x, y, shouldSwitch, dir, switchcount = 0;
                table = document.getElementById("interfaceTable");
                switching = true;
                dir = "asc";
                while (switching) {
                    switching = false;
                    rows = table.rows;
                    for (i = 1; i < (rows.length - 1); i++) {
                        shouldSwitch = false;
                        x = rows[i].getElementsByTagName("TD")[n];
                        y = rows[i + 1].getElementsByTagName("TD")[n];
                        if (dir == "asc") {
                            if (x.innerHTML.toLowerCase() > y.innerHTML.toLowerCase()) {
                                shouldSwitch = true;
                                break;
                            }
                        } else if (dir == "desc") {
                            if (x.innerHTML.toLowerCase() < y.innerHTML.toLowerCase()) {
                                shouldSwitch = true;
                                break;
                            }
                        }
                    }
                    if (shouldSwitch) {
                        rows[i].parentNode.insertBefore(rows[i + 1], rows[i]);
                        switching = true;
                        switchcount++;
                    } else {
                        if (switchcount == 0 && dir == "asc") {
                            dir = "desc";
                            switching = true;
                        }
                    }
                }
            }
        </script>
    </head>
    <body>
        <h1>Interface Error Report</h1>
        <p>Generated on: {timestamp}</p>
        {table}
    </body>
    </html>
    """
    
    # Convert DataFrame to HTML
    table_html = df.to_html(
        classes='sortable',
        index=False,
        table_id='interfaceTable',
        escape=False
    )
    
    # Add onclick handlers to table headers
    table_html = table_html.replace('<th>', '<th onclick="sortTable(this.cellIndex)">')
    
    # Format the final HTML
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    final_html = html_template.format(
        timestamp=timestamp,
        table=table_html
    )
    
    return final_html

def save_html(html: str):
    #save the HTML to a file with timestamp
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'interface_errors_{timestamp}.html'
    with open(filename, 'w') as file:
        file.write(html)
    print(f"HTML report saved to {filename}")

def main():
    # Step 1: Load devices
    devices = load_devices()
    
    # Step 2: Process devices in parallel
    threads = []
    results = []
    for device in devices:
        thread = threading.Thread(target=lambda d=device: results.append(worker(d)))
        threads.append(thread)
        thread.start()
    
    # Step 3: Wait for all threads to complete
    for thread in threads:
        thread.join()
    
    # Step 4: Filter out None results (failed devices)
    successful_devices = [d for d in results if d is not None]
    
    # Step 5: Prepare and save data
    if successful_devices:
        df = prepare_dataframe(successful_devices)
        # Save both CSV and HTML formats
        save_data(df)
        html = toSortableHTML(df)
        save_html(html)
    else:
        print("No devices were successfully processed")

if __name__ == '__main__':
    main()

        
