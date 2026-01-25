import subprocess
import os

# List of PCAP files (from your query)
pcap_files = [
    "dmptcp---dynamic2----adhoc01---trace-enp0s3.pcap",
    "dmptcp---dynamic2----adhoc02---trace-enp0s3.pcap",
    "dmptcp---dynamic2----adhoc03---trace-enp0s3.pcap",
    "dmptcp---dynamic2----adhoc04---trace-enp0s3.pcap",
    "dmptcp---dynamic2----adhoc05---trace-enp0s3.pcap",
    "dmptcp---dynamic2----adhoc06---trace-enp0s3.pcap",
    "dmptcp---dynamic2----adhoc07---trace-enp0s3.pcap",
    "dmptcp---dynamic2----adhoc08---trace-enp0s3.pcap",
    "dmptcp---dynamic2----adhoc09---trace-enp0s3.pcap",
    "dmptcp---dynamic2----AP1---trace-enp0s3.pcap",
    "dmptcp---dynamic2----AP1---trace-enp0s8.pcap",
    "dmptcp---dynamic2----AP2---trace-enp0s3.pcap",
    "dmptcp---dynamic2----AP2---trace-enp0s8.pcap",
    "dmptcp---dynamic2----flyNode01---trace-enp0s3.pcap",
    "dmptcp---dynamic2----flyNode02---trace-enp0s3.pcap",
    "dmptcp---dynamic2----flyNode03---trace-enp0s3.pcap",
    "dmptcp---dynamic2----flyNode04---trace-enp0s3.pcap",
    "dmptcp---dynamic2----gateway---trace-enp0s3.pcap",
    "dmptcp---dynamic2----gateway---trace-enp0s8.pcap"
]

def convert_pcap_to_txt(pcap_file):
    """
    Convert a single PCAP file to TXT using tcpdump.
    Output format: similar to tcpdump -nn -vv -X (detailed headers + hex/ASCII dump).
    """
    if not os.path.exists(pcap_file):
        print(f"File not found: {pcap_file}")
        return

    txt_file = pcap_file.replace(".pcap", ".txt")

    # tcpdump command:
    # -r: read from file
    # -nn: no name resolution (numeric)
    # -vv: very verbose (detailed TCP/UDP info)
    # -X: hex and ASCII dump of packet contents
    cmd = ["tcpdump", "-r", pcap_file, "-nn", "-vv", "-X"]

    try:
        with open(txt_file, "w", encoding="utf-8") as outfile:
            subprocess.run(cmd, stdout=outfile, stderr=subprocess.PIPE, check=True)
        print(f"Successfully converted: {pcap_file} → {txt_file}")
    except subprocess.CalledProcessError as e:
        print(f"Error running tcpdump on {pcap_file}: {e.stderr.decode()}")
    except FileNotFoundError:
        print("tcpdump not found. Please install tcpdump or use the Scapy fallback below.")
    except Exception as e:
        print(f"Unexpected error for {pcap_file}: {e}")

# Run conversion for all files
if __name__ == "__main__":
    print("Starting PCAP to TXT conversion...\n")
    for pcap in pcap_files:
        convert_pcap_to_txt(pcap)
    print("\nConversion complete!")
