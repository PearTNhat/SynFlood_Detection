import pandas as pd
import scapy.all as scapy
import time
import numpy as np
import joblib  # Hoặc bạn có thể dùng pickle
# Biến lưu trữ dữ liệu gói tin
packets = []
packet_count = 0
# Hàm bắt gói tin và lưu thông tin cần thiết
def packet_callback(packet):
    global packets
    global packet_count
    packet_count += 1
    print(f"Số gói tin đã bắt: {packet_count}")
    if packet.haslayer(scapy.IP) and packet.haslayer(scapy.TCP):
        pkt_info = {
            "ts": time.time(),  # Time Stamp
            "IP_flags": packet[scapy.IP].flags,  # IP fragmentation
            "IP_DF": getattr(packet[scapy.IP], 'dontfrag', None),  # Tránh lỗi khi không hỗ trợ,  # IP Don't Fragment
            "TCP_dataofs": packet[scapy.TCP].dataofs,  # TCP data offset
            "TCP_SYN": 1 if packet[scapy.TCP].flags & 0x02 else 0,  # Sync Flag
            "TCP_ACK": 1 if packet[scapy.TCP].flags & 0x10 else 0,  # Acknowledgment Flag
            "sport_class": packet[scapy.TCP].sport % 10,  # Source Port Class (simplified)
            "dst_IP_diversity": 1,  # Placeholder: Number of Destination IP
            "dst_port_diversity": 1,  # Placeholder: Number of Destination Port
            "pck_size_sum_of_EW": len(packet),  # EW packet size total
            "ts_diff": 0,  # Placeholder: Time difference of consecutive packets
            "ts_std_WE": 0,  # Placeholder: Time standard deviation in EW window
            "ts_sum_of_EW": 0,  # Placeholder: Time sum in EW window
            "TCP_window_std_WE": 0,  # Placeholder: TCP Window Std in EW window
            # Rolling windows (placeholder values)
            "pck_size_mean_2": 0,  # Placeholder: Rolling window packet size mean
            "ts_mean_2": 0,  # Placeholder: Rolling window packet time mean
            "ts_std_2": 0,  # Placeholder: Rolling window packet time Std.
            "TCP_window_mean_2": 0,  # Placeholder: Rolling window TCP window mean
            # SYN and ACK related features (placeholders)
            "TCP_SYN_sum": 0,  # Placeholder: Number of TCP Sync Flag
            "TCP_ACK_sum": 0,  # Placeholder: Number of TCP ACK Flags
            "TCP_SYN_ratio": 0,  # Placeholder: TCP_SYN/TCP_SYN_sum ratio
            "TCP_ACK_SR": 0,  # Placeholder: TCP_ACK/Sum ratio
            "ts_mean_6": 0,  # Placeholder: Rolling window packet time mean - Window size =6
            "ts_std_6": 0,  # Placeholder: Rolling window packet time Std. - Window size =6
            "pck_size_mean_9": 0,  # Placeholder: Rolling window packet size mean - Window size =9
            "ts_mean_9": 0,  # Placeholder: Rolling window packet time mean - Window size =9
            "ts_std_9": 0,  # Placeholder: Rolling window packet time Std. - Window size =9
            "TCP_window_mean_9": 0,  # Placeholder: Rolling window TCP window mean - Window size =9
            "TCP_ACK_R": 0  # Placeholder: TCP_ACK_sum/sum
        }
        packets.append(pkt_info)

# Hàm tính toán đặc trưng từ danh sách gói tin
def calculate_features():
    df = pd.DataFrame(packets)
    features = {}
    # Tính toán các đặc trưng thống kê từ dataframe
    if len(df) > 0:
        # Tính các đặc trưng theo các cửa sổ thời gian
        features["ts_diff"] = np.mean(np.diff(df["ts"]))  # Thời gian chênh lệch giữa các gói tin liên tiếp
        features["ts_std_WE"] = np.std(df["ts"])  # Độ lệch chuẩn của thời gian
        features["ts_sum_of_EW"] = np.sum(df["ts"])  # Tổng thời gian
        features["pck_size_sum_of_EW"] = np.sum(df["pck_size_sum_of_EW"])  # Tổng kích thước gói tin

        # Tính các đặc trưng Rolling Windows (sử dụng cửa sổ 2, 6, 9)
        features["pck_size_mean_2"] = df["pck_size_sum_of_EW"].rolling(2).mean().iloc[-1]
        features["ts_mean_2"] = df["ts"].rolling(2).mean().iloc[-1]
        features["ts_std_2"] = df["ts"].rolling(2).std().iloc[-1]
        features["TCP_window_mean_2"] = df["TCP_window_std_WE"].rolling(2).mean().iloc[-1]
        
        # SYN/ACK Features
        features["TCP_SYN_sum"] = np.sum(df["TCP_SYN"])
        features["TCP_ACK_sum"] = np.sum(df["TCP_ACK"])
        if features["TCP_SYN_sum"] > 0:
            features["TCP_SYN_ratio"] = features["TCP_SYN_sum"] / len(df)
        if features["TCP_ACK_sum"] > 0:
            features["TCP_ACK_SR"] = features["TCP_ACK_sum"] / len(df)

        # Rolling Windows size = 6 and 9 (add more calculations as needed)
        features["ts_mean_6"] = df["ts"].rolling(6).mean().iloc[-1]
        features["ts_std_6"] = df["ts"].rolling(6).std().iloc[-1]
        features["pck_size_mean_9"] = df["pck_size_sum_of_EW"].rolling(9).mean().iloc[-1]
        features["ts_mean_9"] = df["ts"].rolling(9).mean().iloc[-1]
        features["ts_std_9"] = df["ts"].rolling(9).std().iloc[-1]
        features["TCP_window_mean_9"] = df["TCP_window_std_WE"].rolling(9).mean().iloc[-1]
        features["TCP_ACK_R"] = features["TCP_ACK_sum"] / len(df) if len(df) > 0 else 0

    return features

# Hàm nhận diện SYN Flood sử dụng mô hình học máy (ví dụ: Random Forest)
def detect_syn_flood(features, model):
    # Chuyển đổi các đặc trưng vào DataFrame và dự đoán
    df_features = pd.DataFrame([features])
    prediction = model.predict(df_features)
    return prediction

# Hàm bắt gói tin và nhận diện tấn công SYN Flood trong thời gian thực
def start_real_time_detection(model,packet_count=100, timeout=10):
    scapy.sniff(iface="Intel(R) Wi-Fi 6 AX203",prn=packet_callback, store=0, filter="tcp", count=packet_count)  # Bắt gói tin trong 10 giây
    print('packet',len(packets))
    if len(packets) == 0:
        print("Không thu thập được gói tin TCP trong thời gian quy định.")
        return
    features = calculate_features()
    prediction = detect_syn_flood(features, model)
    if prediction == 1:
        print("Cảnh báo: Phát hiện tấn công SYN Flood!")
    else:
        print("Không có tấn công SYN Flood.")

model = joblib.load("./model/RF_SYN_1_model.pkl")
start_real_time_detection(model)
print('p',packet_count)
