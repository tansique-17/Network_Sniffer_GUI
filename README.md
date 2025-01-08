# Network_Sniffer_GUI

A graphical Packet Sniffer built using Python, [CustomTkinter](https://github.com/TomSchimansky/CustomTkinter), and [Scapy](https://scapy.net/). This tool allows you to capture network packets, filter them by target IP and interface, and analyze them in a user-friendly GUI. 

---

## Features

- **Real-time Packet Capture**: Captures network packets on specified interfaces or all interfaces.
- **Protocol Detection**: Detects common protocols (TCP, UDP, ICMP, ARP, etc.).
- **Interactive GUI**: Intuitive interface for managing packet capture, pausing, resuming, and saving results.
- **Customizable Filters**: Specify target IPs and interfaces to focus on specific traffic.
- **Packet Display Table**: Visualizes captured packets with details (Source, Destination, Protocol).
- **Save to PCAP**: Export captured packets to a `.pcap` file for further analysis.

---

## Prerequisites

Ensure you have the following installed:

- Python 3.8 or later
- `pip` package manager

Install the required Python libraries using the command:

```bash
pip install customtkinter scapy
```

---

## Usage

### 1. Running the Application

Save the script as `networksniffer.py` and execute it with:

```bash
python networksniffersniffer.py
```

### 2. Application Interface

- **Target IP**: Filter packets based on a specific IP address (leave blank for all).
- **Interface**: Specify a network interface (e.g., `eth0`, `wlan0`), or leave blank to capture on all interfaces.
- **Control Buttons**:
  - `Start Capture`: Begin packet capture.
  - `Pause`: Pause packet sniffing.
  - `Resume`: Resume paused sniffing.
  - `Clean`: Clear the packet table and reset captured packets.
  - `Save`: Save captured packets to a `.pcap` file.

---

## Screenshots

### Main Window

![image](https://github.com/user-attachments/assets/71198b4f-6714-4917-bc58-9a9c2b2fa749)


---

## Notes

- This tool uses Scapy for packet capturing, which requires administrator privileges. Run the script with elevated permissions if required.
- Compatibility may vary across operating systems (Linux and macOS are best supported for packet sniffing).

---

## Contributing

Feel free to open issues or submit pull requests to improve this project!

---

## License

This project is licensed under the MIT License. See [LICENSE](./LICENSE) file for details.
