import netmiko # Ensure this is netmiko, not netmiko.ConnectHandler for specific exceptions
import pandas as pd
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
from netmiko import ConnectHandler, SSHDetect
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException
from datetime import datetime
from ntc_templates.parse import parse_output, ParseError # Import ParseError
import threading
import csv
import logging

# Setup basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants
SSH_TIMEOUT = 15  # Timeout for SSHDetect and initial connection attempts
AUTH_TIMEOUT = 10 # Timeout for authentication phase in SSHDetect
SESSION_TIMEOUT = 60 # Netmiko session_timeout
GLOBAL_DELAY_FACTOR = 2 # General delay factor for send_command

# Common error counter keys that NTC templates might produce.
# NTC templates usually output numbers as strings.
ERROR_COUNTER_KEYS = [
    'crc_errors', 'crc',  # CRC often appears as 'crc_errors' or just 'crc'
    'input_errors', 'in_errors',
    'output_errors', 'out_errors',
    'input_discards', 'in_discards', 'input_drops', # Discards/drops
    'output_discards', 'out_discards', 'output_drops',
    'collisions',
    'late_collisions', 'late_collision',
    'deferred_transmissions', 'deferred',
    'giants',
    'runts',
    'ignored',
    'overruns', 'overrun',
    'frame_errors', 'frame',
    'aborts', 'abort',
    'resets', 'interface_resets'
]

@dataclass
class Device:
    ip: str
    username: str
    password: str
    device_type: Optional[str] = None
    hostname: Optional[str] = None
    # interfaces will now be a list of dicts, each dict for one interface with errors
    interfaces: List[Dict[str, Any]] = field(default_factory=list)

def detect_device_type(device: Device) -> Device:
    logging.info(f"Attempting to detect device type for {device.ip}...")
    detector_args = {
        'host': device.ip,
        'username': device.username,
        'password': device.password,
        'timeout': SSH_TIMEOUT,
        'auth_timeout': AUTH_TIMEOUT,
    }
    try:
        guesser = SSHDetect(**detector_args)
        best_match = guesser.autodetect()
        logging.info(f"SSHDetect best_match for {device.ip}: {best_match}")

        if best_match:
            if best_match == 'cisco_xe':
                device.device_type = 'cisco_ios' # Consolidate XE to IOS for templates
                logging.info(f"Mapped cisco_xe to cisco_ios for {device.ip}")
            else:
                device.device_type = best_match
            logging.info(f"Successfully detected device type for {device.ip} as {device.device_type}")
        else:
            device.device_type = 'cisco_ios'
            logging.warning(f"Could not detect device type for {device.ip}, defaulting to 'cisco_ios'.")

    except (NetmikoTimeoutException, ConnectionRefusedError):
        logging.error(f"Timeout/Connection refused detecting device type for {device.ip}. Defaulting to 'cisco_ios'.")
        device.device_type = 'cisco_ios' # Default on common connection errors
    except NetmikoAuthenticationException:
        logging.error(f"Authentication failed detecting device type for {device.ip}. Defaulting to 'cisco_ios'.")
        device.device_type = 'cisco_ios' # Default on auth errors
    except Exception as e:
        logging.error(f"Error detecting device type for {device.ip}: {str(e)} ({type(e).__name__}). Defaulting to 'cisco_ios'.")
        device.device_type = 'cisco_ios'
    return device

def connect_to_device(device: Device) -> Optional[ConnectHandler]:
    if not device.device_type:
        logging.error(f"Cannot connect to {device.ip}: device_type not set.")
        return None
    logging.info(f"Connecting to {device.ip} ({device.hostname or 'IP'}) as {device.device_type}...")
    connection_params = {
        'device_type': device.device_type,
        'host': device.ip,
        'username': device.username,
        'password': device.password,
        'timeout': SSH_TIMEOUT, # For the initial connection
        'session_timeout': SESSION_TIMEOUT, # For the established session
        'global_delay_factor': GLOBAL_DELAY_FACTOR,
        'banner_timeout': 15,
        'auth_timeout': AUTH_TIMEOUT,
    }
    try:
        connection = ConnectHandler(**connection_params)
        logging.info(f"Successfully connected to {device.ip}.")
        # Attempt to get hostname from prompt if not already set
        if not device.hostname:
            prompt = connection.base_prompt
            if prompt:
                device.hostname = prompt.replace("#", "").replace(">", "").strip()
                logging.info(f"Retrieved hostname '{device.hostname}' from prompt for {device.ip}")
        return connection
    except (NetmikoTimeoutException, ConnectionRefusedError) as e:
        logging.error(f"Timeout/Connection refused connecting to {device.ip} ({device.hostname or 'IP'}): {e}")
    except NetmikoAuthenticationException as e:
        logging.error(f"Authentication failed for {device.ip} ({device.hostname or 'IP'}): {e}")
    except Exception as e:
        logging.error(f"Error connecting to {device.ip} ({device.hostname or 'IP'}): {str(e)} ({type(e).__name__})")
    return None

def get_device_facts(device: Device, connection: ConnectHandler) -> Device:
    logging.info(f"Getting facts for {device.hostname or device.ip}...")
    try:
        # Get hostname if not already set (e.g. from prompt or if detection failed to get it)
        if not device.hostname:
            # A more robust way to get hostname if not from prompt
            try:
                hostname_output = connection.send_command('show version', use_textfsm=True) # TextFSM often gets hostname
                if isinstance(hostname_output, list) and hostname_output and 'hostname' in hostname_output[0]:
                    device.hostname = hostname_output[0]['hostname']
                    logging.info(f"Got hostname '{device.hostname}' via show version for {device.ip}")
                else: # Fallback to trying 'show run | i hostname'
                    hostname_output_raw = connection.send_command('show run | i hostname', use_textfsm=False, use_genie=False)
                    if 'hostname ' in hostname_output_raw:
                        device.hostname = hostname_output_raw.split('hostname ')[1].strip().split('\n')[0]
                        logging.info(f"Got hostname '{device.hostname}' via show run for {device.ip}")
            except Exception as e_host:
                logging.warning(f"Could not determine hostname via commands for {device.ip}: {e_host}")
        if not device.hostname: # Final fallback for hostname
            device.hostname = device.ip
            logging.warning(f"Hostname for {device.ip} defaulted to IP address.")

        # Get interface information
        # Use TextFSM/Genie if available for 'show interfaces' as it's generally more reliable
        # Platform string needs to be accurate for ntc-templates
        platform_for_parsing = device.device_type
        if platform_for_parsing == "cisco_ios" and "XE" in connection.send_command("show version", use_textfsm=False, use_genie=False):
             # Heuristic: if it's IOS XE, specific templates might be better if available under cisco_xe
             # However, for 'show interfaces', 'cisco_ios' template is often generic enough.
             # For simplicity, we'll stick to the detected/mapped type.
             pass

        interface_output_raw = connection.send_command('show interfaces', use_textfsm=False, use_genie=False)
        
        try:
            # NTC-templates expects the platform string Netmiko uses
            parsed_interfaces_list = parse_output(
                platform=platform_for_parsing,
                command='show interfaces',
                data=interface_output_raw
            )
            if parsed_interfaces_list:
                logging.info(f"Successfully parsed 'show interfaces' for {device.hostname}. Found {len(parsed_interfaces_list)} interfaces.")
                device.interfaces = filter_interfaces_with_errors(parsed_interfaces_list)
                logging.info(f"Found {len(device.interfaces)} interfaces with errors for {device.hostname}.")
            else:
                logging.warning(f"Parsing 'show interfaces' for {device.hostname} returned no data.")
                device.interfaces = []
        except ParseError as pe:
            logging.error(f"NTC ParseError for 'show interfaces' on {device.hostname} ({platform_for_parsing}): {pe}. Raw output snippet: {interface_output_raw[:200]}")
            device.interfaces = [] # Ensure it's an empty list on parse failure
        except Exception as e_parse:
            logging.error(f"Unexpected error parsing 'show interfaces' for {device.hostname}: {e_parse}")
            device.interfaces = []

    except Exception as e:
        logging.error(f"Error getting facts for {device.hostname or device.ip}: {e}")
        # Ensure interfaces is an empty list if facts gathering fails significantly
        device.interfaces = []
    return device

def filter_interfaces_with_errors(parsed_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    interfaces_with_errors = []
    if not isinstance(parsed_data, list):
        logging.warning(f"Expected a list from parse_output, got {type(parsed_data)}. Skipping interface filtering.")
        return []

    for interface_details in parsed_data:
        if not isinstance(interface_details, dict):
            logging.warning(f"Skipping non-dictionary item in parsed interface data: {type(interface_details)}")
            continue

        has_errors = False
        interface_name = interface_details.get('interface', interface_details.get('port', 'UnknownInterface'))

        for key in ERROR_COUNTER_KEYS:
            value_str = interface_details.get(key)
            if value_str is not None: # Key exists
                try:
                    # NTC templates usually give numbers as strings.
                    # Some values might be non-numeric like 'n/a' or empty string.
                    if isinstance(value_str, str) and value_str.strip().isdigit():
                        if int(value_str) >= 1:
                            has_errors = True
                            break
                    elif isinstance(value_str, (int, float)): # Already a number
                        if value_str >= 1:
                            has_errors = True
                            break
                except ValueError:
                    logging.debug(f"Could not convert value '{value_str}' for key '{key}' to int on {interface_name}.")
                except TypeError: # if value_str is not string or number
                    logging.debug(f"Unexpected type for value '{value_str}' for key '{key}' on {interface_name}: {type(value_str)}")


        if has_errors:
            interfaces_with_errors.append(interface_details)
            logging.debug(f"Interface {interface_name} has errors, adding to report.")
            
    return interfaces_with_errors


def prepare_dataframe(devices: List[Device]) -> pd.DataFrame:
    rows = []
    for device in devices:
        if device.hostname and device.interfaces: # Ensure interfaces list is not empty
            for interface_data in device.interfaces:
                # Ensure 'interface' column is present, NTC might use 'port' or 'name'
                if 'interface' not in interface_data:
                    if 'port' in interface_data:
                        interface_data['interface'] = interface_data['port']
                    elif 'name' in interface_data: # Less common for physical interfaces
                         interface_data['interface'] = interface_data['name']
                    else: # Fallback if no clear interface identifier
                        interface_data['interface'] = 'Unknown'

                row = {
                    'hostname': device.hostname,
                    'ip': device.ip,
                    # 'interface': interface_data.get('interface', 'N/A'), # Now handled above
                    **interface_data # Spread all keys from interface_data
                }
                rows.append(row)
    if not rows:
        logging.warning("No data to prepare for DataFrame. All devices might have failed or had no interfaces with errors.")
        # Return an empty DataFrame with expected columns if you want to handle empty reports gracefully
        # Or, handle this upstream before calling save_data/save_html
        return pd.DataFrame()
        
    return pd.DataFrame(rows)

def save_data_csv(df: pd.DataFrame, prefix: str = 'interface_errors'):
    if df.empty:
        logging.info("DataFrame is empty. Skipping CSV save.")
        return
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'{prefix}_{timestamp}.csv'
    try:
        df.to_csv(filename, index=False)
        logging.info(f"Data saved to {filename}")
    except Exception as e:
        logging.error(f"Failed to save CSV {filename}: {e}")


def get_creds():
    username = input("Enter the username: ")
    password = input("Enter the password: ") # Consider using getpass for password input
    return username, password

def load_devices_from_csv(filepath: str = 'devices.csv') -> List[Device]:
    devices = []
    username, password = get_creds()
    try:
        with open(filepath, 'r', encoding='utf-8') as file:
            reader = csv.reader(file)
            header = next(reader, None) # Skip header if present
            if header and header[0].lower().strip() in ['ip', 'host', 'deviceip']: # Basic header check
                logging.info(f"Skipped header in {filepath}: {header}")
            else: # No header or not a recognized one, rewind and process first line
                file.seek(0)

            for i, row in enumerate(reader):
                if row: # Ensure row is not empty
                    ip_address = row[0].strip()
                    if ip_address: # Ensure IP is not empty string
                        devices.append(Device(ip=ip_address, username=username, password=password))
                    else:
                        logging.warning(f"Skipping empty IP address in {filepath} at row {i+1 (+1 if header was skipped)}")
                else:
                    logging.warning(f"Skipping empty row in {filepath} at row {i+1 (+1 if header was skipped)}")
    except FileNotFoundError:
        logging.error(f"Device file '{filepath}' not found.")
    except Exception as e:
        logging.error(f"Error reading device file '{filepath}': {e}")
    return devices

def worker(device_in: Device, results_list: list, lock: threading.Lock):
    processed_device = None
    try:
        # Step 1: Detect device type
        device_with_type = detect_device_type(device_in) # Renamed function
        
        if not device_with_type.device_type:
            logging.error(f"Skipping {device_in.ip} due to no device type detected.")
            return # Exit if no device type could be determined

        # Step 2: Connect to device
        connection = connect_to_device(device_with_type) # Renamed function
        
        if connection:
            try:
                # Step 3: Get device facts (hostname, interfaces with errors)
                processed_device = get_device_facts(device_with_type, connection)
            finally:
                # Step 4: Close connection
                connection.disconnect()
                logging.info(f"Disconnected from {processed_device.hostname if processed_device else device_in.ip}.")
        else:
            logging.warning(f"Could not connect to {device_in.ip}, skipping facts gathering.")
            # Keep device_in data but it won't have interfaces
            processed_device = device_with_type # Store it so we know it was attempted

    except Exception as e:
        logging.error(f"Unhandled error in worker for device {device_in.ip}: {e}", exc_info=True)
        # Store original device info if processing failed catastrophically mid-way
        processed_device = device_in if not processed_device else processed_device
    finally:
        with lock:
            if processed_device: # Add even if only IP/hostname is available (e.g. connection failed)
                 results_list.append(processed_device)
            # else: # if device_in was never assigned to processed_device (should not happen with current logic)
            #    results_list.append(device_in) # Fallback, less ideal

def to_sortable_html(df: pd.DataFrame, title: str = "Interface Error Report") -> str:
    if df.empty:
        logging.info("DataFrame is empty. Generating basic HTML report indicating no data.")
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        return f"""
        <!DOCTYPE html><html><head><title>{title}</title></head>
        <body><h1>{title}</h1><p>Generated on: {timestamp}</p>
        <p>No interface errors found or no devices could be processed successfully.</p>
        </body></html>
        """

    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>{title}</title>
        <meta charset="UTF-8">
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #4CAF50; color: white; cursor: pointer; }}
            tr:nth-child(even) {{ background-color: #f2f2f2; }}
            tr:hover {{ background-color: #ddd; }}
            .error {{ color: red; font-weight: bold; }} /* Example: not used by default */
            caption {{ caption-side: top; font-size: 1.5em; margin-bottom: 10px; text-align: left; }}
        </style>
        <script>
            function sortTable(n, tableId) {{
                var table, rows, switching, i, x, y, shouldSwitch, dir, switchcount = 0;
                table = document.getElementById(tableId);
                switching = true;
                dir = "asc";
                // Store the current sort direction on the table header
                var header = table.getElementsByTagName("TH")[n];
                if (header.getAttribute("data-sort-dir") === "asc") {{
                    dir = "desc";
                    header.setAttribute("data-sort-dir", "desc");
                }} else {{
                    dir = "asc";
                    header.setAttribute("data-sort-dir", "asc");
                }}
                // Reset other headers' sort direction
                var ths = table.getElementsByTagName("TH");
                for (var j = 0; j < ths.length; j++) {{
                    if (j !== n) {{ ths[j].removeAttribute("data-sort-dir"); }}
                }}

                while (switching) {{
                    switching = false;
                    rows = table.rows;
                    for (i = 1; i < (rows.length - 1); i++) {{
                        shouldSwitch = false;
                        x = rows[i].getElementsByTagName("TD")[n];
                        y = rows[i + 1].getElementsByTagName("TD")[n];
                        
                        var xContent = x.innerHTML.toLowerCase();
                        var yContent = y.innerHTML.toLowerCase();
                        
                        // Try to sort as numbers if possible
                        var xNum = parseFloat(xContent);
                        var yNum = parseFloat(yContent);

                        if (!isNaN(xNum) && !isNaN(yNum)) {{ // Both are numbers
                            if (dir == "asc") {{
                                if (xNum > yNum) {{ shouldSwitch = true; break; }}
                            }} else if (dir == "desc") {{
                                if (xNum < yNum) {{ shouldSwitch = true; break; }}
                            }}
                        }} else {{ // Sort as strings
                            if (dir == "asc") {{
                                if (xContent > yContent) {{ shouldSwitch = true; break; }}
                            }} else if (dir == "desc") {{
                                if (xContent < yContent) {{ shouldSwitch = true; break; }}
                            }}
                        }}
                    }}
                    if (shouldSwitch) {{
                        rows[i].parentNode.insertBefore(rows[i + 1], rows[i]);
                        switching = true;
                        switchcount++;
                    }} else {{
                        if (switchcount == 0 && dir == "asc") {{
                            // If no switching occurred and direction is asc,
                            // it implies it's already sorted asc or we need to switch to desc
                            // The logic for toggling dir is now at the start of the function
                        }}
                    }}
                }}
            }}
        </script>
    </head>
    <body>
        <h1>{title}</h1>
        <p>Generated on: {timestamp}</p>
        {table_html}
    </body>
    </html>
    """
    
    table_id = "interfaceReportTable"
    # Convert DataFrame to HTML
    # escape=False can be a security risk if data comes from untrusted sources.
    # For internal tools showing device output, it's often acceptable.
    table_html_content = df.to_html(
        table_id=table_id,
        index=False,
        escape=True, # Set to True for safety, False if you need to render HTML within cells
        na_rep='N/A' # Representation for missing values
    )
    
    # Add onclick handlers to table headers for sorting
    # This is a bit crude; a proper HTML parser (like BeautifulSoup) would be more robust.
    header_replacement = f'<th onclick="sortTable(Array.from(this.parentNode.children).indexOf(this), \'{table_id}\')">'
    table_html_content = table_html_content.replace('<th>', header_replacement)
    
    timestamp_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    final_html = html_template.format(
        title=title,
        timestamp=timestamp_str,
        table_html=table_html_content
    )
    
    return final_html

def save_html_report(html_content: str, prefix: str = 'interface_errors_report'):
    if not html_content:
        logging.warning("HTML content is empty. Skipping save.")
        return
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'{prefix}_{timestamp}.html'
    try:
        with open(filename, 'w', encoding='utf-8') as file:
            file.write(html_content)
        logging.info(f"HTML report saved to {filename}")
    except Exception as e:
        logging.error(f"Failed to save HTML report {filename}: {e}")

def main():
    logging.info("Starting interface error detection script.")
    devices_to_process = load_devices_from_csv()
    
    if not devices_to_process:
        logging.warning("No devices loaded from CSV. Exiting.")
        return

    threads = []
    processed_results: List[Device] = [] # Type hint for clarity
    processing_lock = threading.Lock()
        
    for dev_config in devices_to_process:
        thread = threading.Thread(target=worker, args=(dev_config, processed_results, processing_lock))
        threads.append(thread)
        thread.start()
        if len(threads) % 10 == 0: # Optional: limit concurrent threads slightly
            logging.info(f"Launched {len(threads)} threads. Pausing briefly...")
            # time.sleep(0.5) # Can help if SSH server has rate limits, but usually not needed.

    for thread in threads:
        thread.join()
    
    logging.info(f"All {len(threads)} processing threads completed.")
    
    # Filter out devices where processing might have added them without full success (e.g., only IP, no interfaces)
    # We are interested in devices for which we at least got a hostname and potentially interfaces.
    # The current worker logic appends device even if connection failed, so hostname might be just IP.
    # We only want devices that successfully had interfaces parsed (even if list is empty) for the dataframe.
    # Devices that failed connection will have device.interfaces as default empty list.
    # The key is that get_device_facts was attempted and completed.
    
    successful_devices = [d for d in processed_results if d.hostname and d.interfaces is not None] # interfaces can be empty list
    
    if successful_devices:
        logging.info(f"Preparing data for {len(successful_devices)} successfully processed or partially processed devices.")
        df = prepare_dataframe(successful_devices)
        
        if not df.empty:
            save_data_csv(df)
            html_output = to_sortable_html(df)
            save_html_report(html_output)
        else:
            logging.info("DataFrame is empty after processing, no CSV or HTML report with errors generated.")
            # You might still want an HTML report saying "no errors found"
            html_output = to_sortable_html(df) # Will generate the "no data" version
            save_html_report(html_output)

    else:
        logging.warning("No devices were successfully processed to the point of generating a report.")
        # Generate an empty report page
        html_output = to_sortable_html(pd.DataFrame())
        save_html_report(html_output)

    logging.info("Script finished.")

if __name__ == '__main__':
    # For more verbose Netmiko logging during development/debugging:
    # netmiko_logger = logging.getLogger("netmiko")
    # netmiko_logger.setLevel(logging.DEBUG) # Very verbose
    # handler = logging.StreamHandler()
    # formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    # handler.setFormatter(formatter)
    # netmiko_logger.addHandler(handler)
    main()
