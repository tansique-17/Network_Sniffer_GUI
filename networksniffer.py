import customtkinter as ctk
from tkinter import ttk, messagebox, filedialog  # Import messagebox and filedialog
from threading import Thread, Event
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, wrpcap # type: ignore
import time

class PacketSnifferApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Configure theme and window
        ctk.set_appearance_mode("dark")  # Use dark mode
        ctk.set_default_color_theme("dark-blue")  # Use a dark theme
        self.title("Packet Sniffer")
        self.geometry("1000x600")

        # Initialize flags and events
        self.sniffing_event = Event()
        self.sniffing_event.set()  # Start with sniffing active
        self.packet_sniffer_thread = None
        self.packets = []  # List to store captured packets

        # Header
        self.header_frame = ctk.CTkFrame(self, corner_radius=10)
        self.header_frame.pack(fill="x", padx=10, pady=5)

        self.about_button = ctk.CTkButton(self.header_frame, text="About", command=self.show_about, width=100)
        self.about_button.pack(side="left", padx=5, pady=5)

        self.exit_button = ctk.CTkButton(self.header_frame, text="Exit", command=self.exit_app, width=100)
        self.exit_button.pack(side="right", padx=5, pady=5)

        # Filters and Inputs
        self.input_frame = ctk.CTkFrame(self, corner_radius=10)
        self.input_frame.pack(fill="x", padx=10, pady=5)

        self.target_label = ctk.CTkLabel(self.input_frame, text="Target IP:", anchor="w", width=120)
        self.target_label.grid(row=0, column=0, padx=5, pady=5)
        self.target_entry = ctk.CTkEntry(self.input_frame, placeholder_text="Enter IP (leave blank for all)")
        self.target_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        self.interface_label = ctk.CTkLabel(self.input_frame, text="Interface:", anchor="w", width=120)
        self.interface_label.grid(row=1, column=0, padx=5, pady=5)
        self.interface_entry = ctk.CTkEntry(self.input_frame, placeholder_text="Enter interface (e.g., eth0)")
        self.interface_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")

        # Buttons for control (Start, Pause, Resume, Clean, Save) arranged horizontally
        self.button_frame = ctk.CTkFrame(self.input_frame)
        self.button_frame.grid(row=0, column=2, rowspan=3, padx=10, pady=5, sticky="ew")

        self.start_button = ctk.CTkButton(self.button_frame, text="Start Capture", command=self.start_sniffing_thread)
        self.start_button.grid(row=0, column=0, padx=5, pady=5, sticky="ew")

        self.pause_button = ctk.CTkButton(self.button_frame, text="Pause", command=self.pause_sniffing)
        self.pause_button.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        self.resume_button = ctk.CTkButton(self.button_frame, text="Resume", command=self.resume_sniffing)
        self.resume_button.grid(row=0, column=2, padx=5, pady=5, sticky="ew")

        self.clean_button = ctk.CTkButton(self.button_frame, text="Clean", command=self.clean_results)
        self.clean_button.grid(row=0, column=3, padx=5, pady=5, sticky="ew")

        self.save_button = ctk.CTkButton(self.button_frame, text="Save", command=self.save_results)
        self.save_button.grid(row=1, column=0, columnspan=4, padx=5, pady=5, sticky="ew")

        # Packet Display Table
        self.table_frame = ctk.CTkFrame(self, corner_radius=10, fg_color="#2e2e2e")  # Dark grey background
        self.table_frame.pack(fill="both", expand=True, padx=10, pady=5)

        # Define Treeview style
        style = ttk.Style()
        style.theme_use("clam")  # Use a style theme that allows customization

        style.configure("Custom.Treeview",
                        background="#2e2e2e",  # Dark grey background
                        foreground="white",   # White text
                        rowheight=30,         # Increased row height
                        fieldbackground="#2e2e2e",  # Same as background
                        bordercolor="#1c1c1c",  # Border color
                        borderwidth=0,  # Remove extra borders
                        font=("Arial", 12, "bold"))  # Increased font size and bold text

        style.map("Custom.Treeview",
                  background=[("selected", "#1c1c1c")],  # Highlight color for selected rows
                  foreground=[("selected", "white")])

        style.configure("Custom.Treeview.Heading",
                        background="#1c1c1c",  # Darker grey for heading
                        foreground="white",   # White text for heading
                        bordercolor="#1c1c1c",
                        borderwidth=1,
                        font=("Arial", 14, "bold"))  # Increased font size and bold text for headers

        self.table = ttk.Treeview(self.table_frame, columns=("No", "Time", "Source", "Destination", "Protocol"), show="headings", style="Custom.Treeview")
        self.table.heading("No", text="No.")
        self.table.heading("Time", text="Time")
        self.table.heading("Source", text="Source")
        self.table.heading("Destination", text="Destination")
        self.table.heading("Protocol", text="Protocol")

        self.table.column("No", width=50, anchor="center")
        self.table.column("Time", width=150, anchor="center")
        self.table.column("Source", width=150, anchor="center")
        self.table.column("Destination", width=150, anchor="center")
        self.table.column("Protocol", width=100, anchor="center")

        self.table.pack(fill="both", expand=True)

        # Status Bar
        self.status_label = ctk.CTkLabel(self, text="Waiting for input...", anchor="w", font=("Arial", 12, "bold"))
        self.status_label.pack(fill="x", padx=10, pady=5)

        # Packet Counter
        self.packet_count = 0

    def start_sniffing_thread(self):
        """Start packet sniffing in a separate thread."""
        self.status_label.configure(text="Initializing packet capture...")
        self.sniffing_event.set()  # Ensure sniffing starts
        self.packet_sniffer_thread = Thread(target=self.start_sniffing, daemon=True)
        self.packet_sniffer_thread.start()

    def start_sniffing(self):
        """Capture packets."""
        target_ip = self.target_entry.get().strip()
        interface = self.interface_entry.get().strip()

        self.status_label.configure(text=f"Capturing on {interface or 'all interfaces'}...")
        sniff(iface=interface if interface else None, prn=self.process_packet, store=False)

    def process_packet(self, packet):
        """Process each captured packet and display in the table."""
        if self.sniffing_event.is_set():
            self.packet_count += 1
            time = packet.time
            src = packet[IP].src if packet.haslayer(IP) else "N/A"
            dst = packet[IP].dst if packet.haslayer(IP) else "N/A"
            
            # Check for common protocols
            if packet.haslayer(TCP):
                proto = "TCP"
            elif packet.haslayer(UDP):
                proto = "UDP"
            elif packet.haslayer(ICMP):
                proto = "ICMP"
            elif packet.haslayer(ARP):
                proto = "ARP"
            elif packet.haslayer(IP):
                proto = "IP"  # Generic IP packets
            else:
                proto = "Other"  # For any other protocol not explicitly handled

            # Insert packet info into the table (no "Length" column)
            self.table.insert("", "end", values=(self.packet_count, time, src, dst, proto))

            # Store the packet for saving to PCAP
            self.packets.append(packet)

    def pause_sniffing(self):
        """Pause the sniffing."""
        self.sniffing_event.clear()
        self.status_label.configure(text="Sniffing paused.")

    def resume_sniffing(self):
        """Resume the sniffing."""
        self.sniffing_event.set()
        self.status_label.configure(text="Resuming packet capture...")

    def clean_results(self):
        """Clean the table and reset packet count."""
        self.packet_count = 0
        self.table.delete(*self.table.get_children())
        self.packets.clear()  # Clear the stored packets
        self.status_label.configure(text="Results cleared.")

    def save_results(self):
        """Save captured packet data to a PCAP file."""
        if not self.packets:
            messagebox.showwarning("No Data", "No packet data to save.")
            return

        file_path = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP Files", "*.pcap")])
        if file_path:
            wrpcap(file_path, self.packets)  # Write packets to the PCAP file
            messagebox.showinfo("Success", "Packet data saved successfully in PCAP format!")

    def show_about(self):
        """Show about dialog."""
        messagebox.showinfo("About", "Packet Sniffer v1.0\nBuilt using CustomTkinter and Scapy.")  # Use messagebox

    def exit_app(self):
        """Exit the application."""
        self.destroy()

# Run the application
if __name__ == "__main__":
    app = PacketSnifferApp()
    app.mainloop()
