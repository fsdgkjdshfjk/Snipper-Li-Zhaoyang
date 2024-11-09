from datetime import datetime
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from scapy.all import sniff, IP, TCP, UDP, ICMP, IPv6, Raw, ARP
import threading
import psutil

# 初始化主窗口
root = tk.Tk()
root.title("网络嗅探器")
root.geometry("1200x600")

# 获取系统的网络接口
interfaces = [iface for iface in psutil.net_if_addrs().keys()]

# 顶部框架布局
top_frame = tk.Frame(root)
top_frame.pack(side=tk.TOP, fill=tk.X)

# 接口选择标签和下拉菜单
interface_label = tk.Label(top_frame, text="选择网络接口：")
interface_label.pack(side=tk.LEFT, padx=5)

interface_var = tk.StringVar(value=interfaces[0])
interface_combo = ttk.Combobox(top_frame, textvariable=interface_var, values=interfaces, width=20)
interface_combo.pack(side=tk.LEFT, padx=5)

# 协议选择过滤
protocol_label = tk.Label(top_frame, text="选择协议过滤：")
protocol_label.pack(side=tk.LEFT, padx=5)

protocol_var = tk.StringVar(value="ALL")
protocol_combo = ttk.Combobox(top_frame, textvariable=protocol_var,
                              values=("ALL", "TCP", "UDP", "HTTP", "ICMP", "IPv4", "IPv6", "ARP"), width=10)
protocol_combo.pack(side=tk.LEFT, padx=5)

# 源地址、源端口、目标地址和目标端口的筛选输入框
filter_frame = tk.Frame(top_frame)
filter_frame.pack(side=tk.LEFT, padx=10)

src_ip_label = tk.Label(filter_frame, text="源地址：")
src_ip_label.grid(row=0, column=0)
src_ip_entry = tk.Entry(filter_frame, width=15)
src_ip_entry.grid(row=0, column=1)

src_port_label = tk.Label(filter_frame, text="源端口：")
src_port_label.grid(row=0, column=2)
src_port_entry = tk.Entry(filter_frame, width=10)
src_port_entry.grid(row=0, column=3)

dst_ip_label = tk.Label(filter_frame, text="目标地址：")
dst_ip_label.grid(row=1, column=0)
dst_ip_entry = tk.Entry(filter_frame, width=15)
dst_ip_entry.grid(row=1, column=1)

dst_port_label = tk.Label(filter_frame, text="目标端口：")
dst_port_label.grid(row=1, column=2)
dst_port_entry = tk.Entry(filter_frame, width=10)
dst_port_entry.grid(row=1, column=3)

# 按钮布局
button_frame = tk.Frame(top_frame)
button_frame.pack(side=tk.RIGHT, padx=10)

start_button = tk.Button(button_frame, text="启动嗅探器", command=lambda: start_capture())
start_button.grid(row=0, column=0, padx=5)

stop_button = tk.Button(button_frame, text="停止嗅探器", command=lambda: stop_capture())
stop_button.grid(row=0, column=1, padx=5)

filter_button = tk.Button(button_frame, text="筛选", command=lambda: show_filtered_packets())
filter_button.grid(row=0, column=2, padx=5)

clear_button = tk.Button(button_frame, text="清空", command=lambda: clear_display())
clear_button.grid(row=0, column=3, padx=5)


# Packet List Frame
packet_list_frame = ttk.Frame(root)
packet_list_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

# 初始化表格 (Packet List)
packet_tree = ttk.Treeview(packet_list_frame,
                           columns=(
                           "No.", "Time", "Source", "Source Port", "Destination", "Destination Port", "Protocol",
                           "Length", "Info"),
                           show="headings", height=10)
packet_tree.heading("No.", text="No.")
packet_tree.heading("Time", text="Time")
packet_tree.heading("Source", text="Source")
packet_tree.heading("Source Port", text="Source Port")
packet_tree.heading("Destination", text="Destination")
packet_tree.heading("Destination Port", text="Destination Port")
packet_tree.heading("Protocol", text="Protocol")
packet_tree.heading("Length", text="Length")
packet_tree.heading("Info", text="Information")

# 设置列宽度
packet_tree.column("No.", width=50, anchor="center")
packet_tree.column("Time", width=100, anchor="center")
packet_tree.column("Source", width=150)
packet_tree.column("Source Port", width=80, anchor="center")
packet_tree.column("Destination", width=150)
packet_tree.column("Destination Port", width=80, anchor="center")
packet_tree.column("Protocol", width=80, anchor="center")
packet_tree.column("Length", width=80, anchor="center")
packet_tree.column("Info", width=400)

packet_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

# 滚动条
scrollbar = ttk.Scrollbar(packet_list_frame, orient="vertical", command=packet_tree.yview)
packet_tree.configure(yscroll=scrollbar.set)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

# Packet Details Frame (分成两部分，下半部分)
bottom_frame = tk.Frame(root)
bottom_frame.pack(side=tk.BOTTOM, fill=tk.BOTH, expand=True)

# Packet in Binary Frame
packet_binary_frame = scrolledtext.ScrolledText(bottom_frame, height=10)
packet_binary_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

# Packet Details Frame
packet_details_frame = scrolledtext.ScrolledText(bottom_frame, height=10)
packet_details_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

# 捕获数据包的回调函数
packet_counter = 0
all_packets = []  # 用于存储所有捕获的数据包
flows = {}  # 用于存储所有流
capturing = False  # 控制捕获状态的标志变量


def clear_display():
    """清空显示内容和数据"""
    global all_packets, flows, packet_counter
    all_packets.clear()
    flows.clear()
    packet_counter = 0
    packet_tree.delete(*packet_tree.get_children())
    packet_details_frame.delete("1.0", tk.END)
    packet_binary_frame.delete("1.0", tk.END)

def packet_callback(packet):
    global packet_counter
    if not capturing:
        return
    packet_counter += 1
    all_packets.append(packet)
    add_packet_to_flow(packet)
    show_filtered_packets()


def add_packet_to_flow(packet):
    # 获取流的标识符
    if packet.haslayer(IP):
        proto = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "ICMP"
        src = packet[IP].src
        dst = packet[IP].dst
        sport = packet[TCP].sport if packet.haslayer(TCP) else packet[UDP].sport if packet.haslayer(UDP) else None
        dport = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport if packet.haslayer(UDP) else None
        flow_id = (src, sport, dst, dport, proto)
    else:
        return

    # 如果流不存在，则创建新流
    if flow_id not in flows:
        flows[flow_id] = []

    # 添加数据包到流
    flows[flow_id].append(packet)


def get_info_field(packet):
    """根据数据包协议返回详细信息"""
    if packet.haslayer(TCP):
        # TCP 包详细信息
        return f"TCP Seq={packet[TCP].seq} Ack={packet[TCP].ack} Win={packet[TCP].window} Flags={packet[TCP].flags}"
    elif packet.haslayer(UDP):
        # UDP 包详细信息
        return f"UDP Source Port={packet[UDP].sport} Destination Port={packet[UDP].dport} Length={packet[UDP].len}"
    elif packet.haslayer(ICMP):
        # ICMP 包详细信息
        icmp_type = packet[ICMP].type
        icmp_code = packet[ICMP].code
        return f"ICMP Type={icmp_type} Code={icmp_code}"
    elif packet.haslayer(IPv6):
        # IPv6 包详细信息
        if packet.haslayer("ICMPv6ND_NS"):
            return f"IPv6 Neighbor Solicitation for {packet[IPv6].dst}"
        elif packet.haslayer("ICMPv6ND_NA"):
            return f"IPv6 Neighbor Advertisement for {packet[IPv6].dst}"
        else:
            return f"IPv6 {packet[IPv6].src} -> {packet[IPv6].dst}"
    elif packet.haslayer(ARP):
        # ARP 包详细信息
        return f"ARP {packet[ARP].psrc} is at {packet[ARP].hwsrc} -> {packet[ARP].pdst}"
    elif is_http_packet(packet):
        # HTTP 包详细信息
        return "HTTP Packet Detected"
    else:
        # 其他包简单显示源和目标
        src = packet[IP].src if IP in packet else packet[IPv6].src if IPv6 in packet else "N/A"
        dst = packet[IP].dst if IP in packet else packet[IPv6].dst if IPv6 in packet else "N/A"
        return f"{src} -> {dst}"

def show_filtered_packets():
    for item in packet_tree.get_children():
        packet_tree.delete(item)

    selected_protocol = protocol_var.get()
    src_ip_filter = src_ip_entry.get()
    src_port_filter = src_port_entry.get()
    dst_ip_filter = dst_ip_entry.get()
    dst_port_filter = dst_port_entry.get()

    for i, packet in enumerate(all_packets, start=1):
        show_packet = False
        if selected_protocol == "ALL":
            show_packet = True
        elif selected_protocol == "HTTP" and is_http_packet(packet):
            show_packet = True
        elif selected_protocol == "TCP" and packet.haslayer(TCP):
            show_packet = True
        elif selected_protocol == "UDP" and packet.haslayer(UDP):
            show_packet = True
        elif selected_protocol == "ICMP" and packet.haslayer(ICMP):
            show_packet = True
        elif selected_protocol == "IPv4" and packet.haslayer(IP):
            show_packet = True
        elif selected_protocol == "IPv6" and packet.haslayer(IPv6):
            show_packet = True
        elif selected_protocol == "ARP" and packet.haslayer(ARP):
            show_packet = True

        if show_packet:
            src = packet[IP].src if IP in packet else packet[IPv6].src if IPv6 in packet else "N/A"
            dst = packet[IP].dst if IP in packet else packet[IPv6].dst if IPv6 in packet else "N/A"
            sport = packet[TCP].sport if packet.haslayer(TCP) else packet[UDP].sport if packet.haslayer(UDP) else "N/A"
            dport = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport if packet.haslayer(UDP) else "N/A"

            if src_ip_filter and src != src_ip_filter:
                continue
            if src_port_filter and str(sport) != src_port_filter:
                continue
            if dst_ip_filter and dst != dst_ip_filter:
                continue
            if dst_port_filter and str(dport) != dst_port_filter:
                continue

            timestamp = datetime.now().strftime("%H:%M:%S")
            length = len(packet)

            # 优先检测应用层协议
            protocol = "Others"
            if is_http_packet(packet):
                protocol = "HTTP"
            elif packet.haslayer(TCP):
                protocol = "TCP"
            elif packet.haslayer(UDP):
                protocol = "UDP"
            elif packet.haslayer(ICMP):
                protocol = "ICMP"
            elif packet.haslayer(IP):
                protocol = "IPv4"
            elif packet.haslayer(IPv6):
                protocol = "IPv6"
            elif packet.haslayer(ARP):
                protocol = "ARP"

            # 使用 get_info_field 获取详细的 Info 字段
            info = get_info_field(packet)
            packet_tree.insert("", "end", values=(i, timestamp, src, sport, dst, dport, protocol, length, info))


def is_http_packet(packet):
    if packet.haslayer(Raw) and b"HTTP" in bytes(packet[Raw].load):
        return True
    return False


def on_packet_select(event):
    selected_item = packet_tree.selection()
    if selected_item:
        index = int(packet_tree.item(selected_item)["values"][0]) - 1
        packet = all_packets[index]

        # 清空文本框内容
        packet_details_frame.delete("1.0", tk.END)
        packet_binary_frame.delete("1.0", tk.END)

        # 显示包详细信息
        packet_details_frame.insert(tk.END, packet.show2(dump=True))

        # 显示二进制数据，16进制显示
        hex_data = ""
        ascii_data = ""
        binary_data = ""
        for i, byte in enumerate(bytes(packet)):
            if i % 16 == 0 and i > 0:
                binary_data += f"{hex_data}  {ascii_data}\n"
                hex_data = ""
                ascii_data = ""
            hex_data += f"{byte:02X} "
            ascii_data += chr(byte) if 32 <= byte <= 126 else "."
        binary_data += f"{hex_data:<48}  {ascii_data}\n"  # 输出最后一行
        packet_binary_frame.insert(tk.END, binary_data)


packet_tree.bind("<<TreeviewSelect>>", on_packet_select)


def start_capture():
    global capturing
    capturing = True
    threading.Thread(target=lambda: sniff(prn=packet_callback, iface=interface_var.get(), store=0)).start()


def stop_capture():
    global capturing
    capturing = False




root.mainloop()