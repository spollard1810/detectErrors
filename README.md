# Network Interface Error Detector

A Python tool that automatically detects and reports interface errors across network devices. The tool connects to multiple devices in parallel, collects interface statistics, and generates both CSV and HTML reports highlighting interfaces with error counters.

## Features

- **Parallel Processing**: Checks multiple devices simultaneously
- **Automatic Device Detection**: Automatically detects device type (Cisco IOS, XE, etc.)
- **Comprehensive Error Detection**: Monitors multiple error counters:
  - CRC errors
  - Input/Output errors
  - Input/Output drops
  - Collisions
  - Giants and runts
  - Interface resets

- **Dual Output Formats**:
  - CSV files for data analysis
  - Interactive HTML reports with sortable columns
  - Both formats include timestamps for tracking

- **Error Handling**: Robust error handling with detailed error messages
- **Clean Interface**: Modern, responsive HTML interface with:
  - Sortable columns
  - Alternating row colors
  - Hover effects
  - Error highlighting

## Requirements

- Python 3.x
- Required Python packages:
  - netmiko
  - pandas
  - ntc_templates

## Input

The tool expects a `devices.csv` file containing a list of device IP addresses to check. 