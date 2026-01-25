import re
import os
from collections import defaultdict
import math

# 协议和拓扑列表
protocols = ['dmptcp', 'tcp', 'mptcp-cubic', 'mptcp-bbr', 'mptcp-olia', 'mptcp-balia', 'mptcp-rr', 'mptcp-red', 'mptcp-blest', 'mptcp-ecf']
topologies = ['static', 'dynamic1', 'dynamic2']

# 分析 tcpdump 文件函数 (提取 Loss Rate 和 OOO)
def analyze_tcpdump(filename):
    if not os.path.exists(filename):
        return {'loss_rate': 0, 'ooo_packets': 0}

    flows = defaultdict(lambda: {'max_seq': 0, 'retrans': 0, 'total_sent': 0})
    ooo_count = 0
    with open(filename, 'r') as f:
        lines = f.readlines()
    i = 0
    while i < len(lines):
        line = lines[i].rstrip()
        i += 1
        if line and re.match(r'^\d{2}:\d{2}:\d{2}\.\d+', line):
            if i < len(lines) and lines[i].strip().startswith('112.26.'):
                line += ' ' + lines[i].strip()
                i += 1
        if not line:
            continue
        # 通用re模式
        match = re.search(r'(\d{2}:\d{2}:\d{2}\.\d+) IP \(tos 0x0, ttl \d+, id \d+, offset 0, flags \[DF\], proto TCP \(6\), length (\d+)\) 112\.26\.4\.6\.(\d+) > 112\.26\.0\.([12])\.5201: Flags \[[P.]?\], cksum 0x[0-9a-f]+ \(correct\), seq (\d+)(:(\d+))?, ack (\d+), win (\d+), options \[.*\], length (\d+)', line)
        if match:
            timestamp, ip_len, src_port, dst_suffix, seq_start, seq_end_group, seq_end, ack, win, tcp_len = match.groups()
            dst_ip = f'112.26.0.{dst_suffix}'
            tcp_len = int(tcp_len)
            if tcp_len > 0:
                flow_key = (src_port, dst_ip)
                seq = int(seq_start)
                pkt_bytes = tcp_len
                flows[flow_key]['total_sent'] += 1
                if seq < flows[flow_key]['max_seq']:
                    flows[flow_key]['retrans'] += 1
                flows[flow_key]['max_seq'] = max(flows[flow_key]['max_seq'], seq + pkt_bytes)
        # SACK 检测
        if re.search(r'IP .* 112\.26\.0\.[12]\.\d+ > 112\.26\.4\.6\.\d+: Flags .*, options \[.*sack.*\]', line):
            ooo_count += 1
    total_sent = sum(f['total_sent'] for f in flows.values())
    total_retrans = sum(f['retrans'] for f in flows.values())
    loss_rate = total_retrans / total_sent if total_sent > 0 else 0
    return {
        'loss_rate': loss_rate,
        'ooo_packets': ooo_count
    }

# 分析 iperf3-time.txt 文件函数 (提取 sender Transfer, Bitrate, Retr, Time)
def analyze_iperf(filename):
    if not os.path.exists(filename):
        return {'total_bytes': 0, 'bitrate': 0.0, 'retr': 0, 'time': 0.0}

    with open(filename, 'r') as f:
        content = f.read()
    sender_match = re.search(r'\[\s*5\s*\]\s*0\.00-(\d+\.\d+)\s*sec\s*(\d+)\s*KBytes\s*(\d+\.\d+)\s*KBytes/sec\s*(\d+)\s*sender', content)
    if sender_match:
        time = float(sender_match.group(1))
        transfer_kbytes = int(sender_match.group(2))
        bitrate = float(sender_match.group(3))
        retr = int(sender_match.group(4))
        total_bytes = transfer_kbytes * 1024  # KBytes to bytes
        return {
            'total_bytes': total_bytes,
            'bitrate': bitrate,
            'retr': retr,
            'time': time
        }
    return {'total_bytes': 0, 'bitrate': 0.0, 'retr': 0, 'time': 0.0}

# 分析 adhoc01 background iperf3-time.txt (提取 background Transfer, Time, 计算 Bitrate)
def analyze_background_iperf(filename):
    if not os.path.exists(filename):
        return {'background_bitrate': 0.0}

    with open(filename, 'r') as f:
        content = f.read()
    sender_match = re.search(r'\[\s*5\s*\]\s*0\.00-(\d+\.\d+)\s*sec\s*(\d+)\s*KBytes', content)
    if sender_match:
        time = float(sender_match.group(1))
        transfer_kbytes = int(sender_match.group(2))
        background_bitrate = (transfer_kbytes / time) if time > 0 else 0.0
        return {'background_bitrate': background_bitrate}
    return {'background_bitrate': 0.0}

# 主逻辑
results = {}
for topo in topologies:
    results[topo] = {}
    for proto in protocols:
        tcpdump_filename = f"{proto}---{topo}----adhoc06---tcpdump-enp0s3.txt"
        iperf_filename = f"{proto}---{topo}----adhoc06---iperf3-time.txt"
        background_filename = f"{proto}---{topo}----adhoc01---iperf3-time.txt"  # background TCP
        tcpdump_data = analyze_tcpdump(tcpdump_filename)
        iperf_data = analyze_iperf(iperf_filename)
        background_data = analyze_background_iperf(background_filename)
        fairness = iperf_data['bitrate'] / background_data['background_bitrate'] if background_data['background_bitrate'] > 0 else 0.0
        results[topo][proto] = {**tcpdump_data, **iperf_data, 'fairness': fairness}
# '使  用' Fairness 通过 MPTCP 流平均发送速率除以背景 TCP 流平均发送速率计算，接近 1 表示公平，>1 表示 MPTCP 占用更多带宽，<1 表示更少。	'使  用 这种方法'
# '不使用' 建议归一化，Fairness 的值 越接近与 1 越更公平。请您给出 计算过程，请您 改进 python 代码（一定保证已有功能不变）			'不使用 这种方法'

# 输出结果
for topo in topologies:
    print(f"Topology: {topo}")
    for proto in protocols:
        data = results[topo][proto]
        print(f"{proto}: Loss Rate={data['loss_rate']:.4f}, OOO={data['ooo_packets']}, Total Bytes={data['total_bytes']}, Retr={data['retr']}, Bitrate={data['bitrate']:.2f}, Time={data['time']:.2f}, Fairness={data['fairness']:.4f}")
