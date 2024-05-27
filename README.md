# ARP Spoof Detector

## Project Overview

The ARP Spoof Detector is a Python-based tool designed to identify and alert users to ARP spoofing attacks in a network. ARP spoofing, also known as ARP poisoning, is a type of attack in which an attacker sends falsified ARP (Address Resolution Protocol) messages over a local area network. This results in the linking of an attacker's MAC address with the IP address of a legitimate computer or server on the network, potentially leading to data interception, modification, or denial of service.

## Features

- Real-time detection of ARP spoofing attacks
- Immediate alerts when an attack is detected

## Installation

To get started with the ARP Spoof Detector, you need to clone the repository and install the necessary dependencies.

### Prerequisites

- Python 3.x
- Scapy library

### Clone the Repository

```sh
git clone https://github.com/arifbinekram/ARP_Spoof_Detector.git
cd ARP_Spoof_Detector
```

### Install Dependencies

```sh
pip install -r requirements.txt
```

## Usage

### Running the ARP Spoof Detector

To start monitoring for ARP spoofing attacks, run the following command:

```sh
python detector.py
```

If an ARP spoofing attack is detected, you will receive continuous alerts in the terminal:

```
[+] You are under attack !!
[+] You are under attack !!
[+] You are under attack !!
...
```

### Example of an Attacker

An example command for an attacker to initiate an ARP spoofing attack is provided below. **Note: This is for educational purposes only. Do not use this to perform unauthorized attacks.**

```sh
python arpspoof.py -t 10.0.2.6 -s 10.0.2.1
```

- `-t`: Target IP address (e.g., victim's machine)
- `-s`: Source IP address (e.g., gateway)

## Contributing

Contributions are welcome! Please fork the repository and create a pull request with your changes. Ensure your code adheres to the existing style and includes appropriate tests.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.

## Contact

For any questions or suggestions, please contact [arifbinekram](https://github.com/arifbinekram).

---

**Disclaimer:** This tool is intended for educational purposes only. Use it responsibly and do not perform unauthorized attacks. The author is not responsible for any misuse of this tool.
