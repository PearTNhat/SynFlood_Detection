import csv
import threading
import queue
import numpy as np
from scapy.all import sniff,wrpcap
from scapy.layers.inet import IP, TCP, UDP
from utils import port_class,flag_fixer,find_the_way,folder,flagsum,diff,std_EW,sum_of_EW,mean,std,cols
from tqdm import tqdm
import pandas as pd
import joblib
import os
from datetime import datetime
current_file = __file__
f = os.path.dirname(os.path.abspath(current_file))
# Định nghĩa header cho CSV
header = ["ts", "IP_src", "IP_dst", "pck_size", "IP_flags", "IP_Z", "IP_MF", "IP_DF", 
          "TCP_dataofs", "TCP_FIN", "TCP_SYN", "TCP_RST", "TCP_PSH", "TCP_ACK", "TCP_URG", 
          "TCP_ECE", "TCP_CWR", "TCP_window", "sport_class", "sport_bare", "dport_bare", 
          "TCP_sport", "TCP_dport", "UDP_sport", "UDP_dport"]

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80
#IP
Z = 0x00
MF= 0x01
DF= 0x02
PCAP_FOLDER = "./pcaps"  # Thư mục lưu file PCAP
BUFFER_SIZE = 1000  # Giới hạn số lượng gói tin trong hàng đợi
WINDOW_SIZE=100
packet_queue = queue.Queue(maxsize=BUFFER_SIZE)
pcap_packets = []
pcap_history= queue.Queue(maxsize=WINDOW_SIZE) # Lưu lịch sử các file PCAP đã lưu để tiến hành phân tích
# Hàm bắt gói tin và thêm vào hàng đợi
def packet_sniffer():
    def enqueue_packet(packet):
        if not packet_queue.full():
            packet_queue.put(packet)
            pcap_packets.append(packet)

        # Khi đủ 100 gói tin, lưu vào file PCAP
        if len(pcap_packets) >= 100:
            save_pcap()

    sniff(iface="Wi-Fi", prn=enqueue_packet, store=0)

# Hàm lưu gói tin vào file PCAP
def save_pcap():
    global pcap_packets
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap_file = os.path.join(PCAP_FOLDER, f"captured_{timestamp}.pcap")
    wrpcap(pcap_file, pcap_packets)
    pcap_history.put(pcap_file)
    # print(f"Saved {len(pcap_packets)} packets to {pcap_file}")
    pcap_packets = []  # Xóa danh sách để chuẩn bị cho lần tiếp theo
# Hàm xử lý gói tin từ hàng đợi
def packet_processor():
    while True:
        if packet_queue.qsize() >= WINDOW_SIZE:
            packets = [packet_queue.get() for _ in range(WINDOW_SIZE)]
            preprocess_and_predict(packets)
            print('_________________________________________________________________________________________')

def preprocess_and_predict(packets):
    # Mở file CSV để ghi dữ liệu
    pcapPath =f + pcap_history.get()
    filename=pcapPath.replace(".pcap","_FE.csv")
    print('Trích xuất đặc trừng file ',pcapPath)
    #  ghi các đặc trưng vào file csv
    with open(filename, mode='w', newline='') as file:
        print("Đang phân tích gói tin...")
        writer = csv.writer(file)
        writer.writerow(header)  # Ghi header vào file CSV
        # Hàm xử lý gói tin khi nhận được
        for packet in packets:
            # global FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, Z, MF, DF
            ts=float(packet.time) # Thời gian của gói tin
            try:pck_size=packet.len #
            except:pck_size=0
            if packet.haslayer(IP):
                IP_Z=0
                IP_MF= 0
                IP_DF= 0
                # pck_size = len(packet)  # Kích thước gói tin
                IP_flags = packet[IP].flags
                if IP_flags & Z:IP_Z = 1
                if IP_flags & MF:IP_MF = 1
                if IP_flags & DF:IP_DF = 1 #
                
                IP_src = packet[IP].src
                IP_dst = packet[IP].dst
                
            else:
                IP_Z = 0
                IP_MF= 0
                IP_DF= 0
                IP_flags=0
                IP_src=0
                IP_dst=0
            if packet.haslayer(TCP):
                TCP_FIN = 0
                TCP_SYN = 0 #
                TCP_RST = 0
                TCP_PSH = 0
                TCP_ACK = 0 #
                TCP_URG = 0
                TCP_ECE = 0
                TCP_CWR = 0
                TCP_sport=packet[TCP].sport
                TCP_dport=packet[TCP].dport
                
                TCP_dataofs=packet[TCP].dataofs #
                TCP_flags=packet[TCP].flags
                TCP_window=packet[TCP].window #
                
                if TCP_flags & FIN:TCP_FIN = 1
                if TCP_flags & SYN:TCP_SYN = 1
                if TCP_flags & RST:TCP_RST = 1
                if TCP_flags & PSH:TCP_PSH = 1
                if TCP_flags & ACK:TCP_ACK = 1
                if TCP_flags & URG:TCP_URG = 1
                if TCP_flags & ECE:TCP_ECE = 1
                if TCP_flags & CWR:TCP_CWR = 1
            else:
                TCP_sport=0
                TCP_dport=0
            
                TCP_dataofs=0
            
                TCP_flags=0
                TCP_window=0
            
                TCP_FIN = 0
                TCP_SYN = 0
                TCP_RST = 0
                TCP_PSH = 0
                TCP_ACK = 0
                TCP_URG = 0
                TCP_ECE = 0
                TCP_CWR = 0
                
            if packet.haslayer(UDP):
                UDP_sport=packet[UDP].sport
                UDP_dport=packet[UDP].dport
                UDP_len=packet[UDP].len
                UDP_chksum=packet[UDP].chksum
            else:
                UDP_sport=0
                UDP_dport=0
                UDP_len=0
                UDP_chksum=0
                # Tạo dòng dữ liệu để ghi vào CSV
            sport_class=port_class(TCP_sport+UDP_sport) #
            sport_bare=TCP_sport+UDP_sport
            dport_bare=TCP_dport+UDP_dport
            row = [ts, 
                IP_src,
                IP_dst,
                pck_size,
                IP_flags,#
                IP_Z,
                IP_MF,
                IP_DF  ,#
                TCP_dataofs,#
                TCP_FIN,
                TCP_SYN,#
                TCP_RST,
                TCP_PSH,
                TCP_ACK,#
                TCP_URG,
                TCP_ECE,
                TCP_CWR   ,
                TCP_window,
                sport_class,
                sport_bare,
                dport_bare,
                TCP_sport,
                TCP_dport,
                UDP_sport,
                UDP_dport
                ]

            # Ghi vào file CSV
            writer.writerow(row)

    output=filename.replace("_FE.csv","_WS.csv")
    print("Đang lấy source destination ...")
    os.system(f"tshark -r {pcapPath} -T fields -e _ws.col.Source -e _ws.col.Destination -e _ws.col.Protocol -E header=y -E separator=, -E quote=d -E occurrence=f > {output}")

    for i in tqdm([filename]):
        print(i)
        df=pd.read_csv(i)
        WS_s_d=i.replace("_FE.csv","_WS.csv")
        s_d=pd.read_csv(WS_s_d)
        df["WS_src"]=s_d["_ws.col.Source"]
        df["WS_dst"]=s_d["_ws.col.Destination"]
        df["Protocol"]=s_d["_ws.col.Protocol"]
        df.to_csv(i,index=None)
        flag_fixer(i)
        os.remove(WS_s_d)
        
    print("Đang thêm dst_port_diversity, dst_IP_diversity ...")
    name_list=find_the_way('./pcaps','_FE.csv')
    for sayac,i in enumerate (name_list):
        print(f"{sayac+1}/{len(name_list)}-{i}")
        dst_IP_diversity=[]
        dst_port_diversity=[]
        src_IP_v_dst_IP={}

        src_IP_v_dst_port={}
        df=pd.read_csv(i)
        for j in tqdm(range(len(df))):
            if df['IP_src'][j] in src_IP_v_dst_IP:
                if df['IP_dst'][j] not in src_IP_v_dst_IP[df['IP_src'][j]]:
                    src_IP_v_dst_IP[df['IP_src'][j]].append(df['IP_dst'][j])
            else:
                src_IP_v_dst_IP[df['IP_src'][j]]=[]
                src_IP_v_dst_IP[df['IP_src'][j]].append(df['IP_dst'][j])
            dst_IP_diversity.append(len(src_IP_v_dst_IP[df['IP_src'][j]]))
            ###############################################################################
            #  gắn port tương tự như IP
            if df['IP_src'][j] in src_IP_v_dst_port:
                if df['dport_bare'][j] not in src_IP_v_dst_port[df['IP_src'][j]]:
                    src_IP_v_dst_port[df['IP_src'][j]].append(df['dport_bare'][j])
            else:
                src_IP_v_dst_port[df['IP_src'][j]]=[]
                src_IP_v_dst_port[df['IP_src'][j]].append(df['dport_bare'][j])
            dst_port_diversity.append(len(src_IP_v_dst_port[df['IP_src'][j]]))
        
        df["dst_IP_diversity"]=dst_IP_diversity
        df["dst_port_diversity"]=dst_port_diversity
        df.to_csv(i,index=None)

    print("Đang xử lý dữ liệu bằng SW ...")
    # chuyển file vào thư mục FE
    files_add=find_the_way('./pcaps','FE.csv')
    existFE=find_the_way('./FE','_FE.csv')
    for i in existFE:
        os.remove(i)
    #  chuyển _FE từ pcaps sang FE 
    for i in files_add:
        os.rename(i,i.replace("./pcaps",'./FE'))
        
    files_add=find_the_way('./FE','FE.csv')
    # sliding window
    outputfolder="SW"
    folder(outputfolder)
    for windows_size in [2,6,9]:
        for j in files_add:
            print(j[5:])
            df=pd.read_csv(j)#,usecols=n)

            df.drop(columns=["UDP_sport", "TCP_sport", "TCP_dport"], inplace=True)
            df.to_csv("temp.csv")

            df=pd.read_csv("temp.csv")
            
            df["ID"] = df["WS_src"]+"=>"+df["WS_dst"]
            
            df.drop(columns=["WS_src", "WS_dst"], inplace=True)
        

            df[df.columns[-1]]=df[df.columns[-1]].astype(str)
            IDS=sorted(list(df[df.columns[-1]].unique()))
            func_sw=[mean,std] #functions
            func_ew=[diff,
                    std_EW,sum_of_EW] #functions
            func_name_sw=["mean","std"]
            func_name_ew=["diff",
                        "std_WE",
                        "sum_of_EW"]

            f_list=[
                "pck_size",
                "ts",
                'TCP_window',
                ]
        #    syn chỉ cần các giá trị này
            fark=[
            'pck_size_mean',
            'pck_size_std',
            'ts_mean',
            'ts_std',
            'TCP_window_mean',
            'TCP_window_std',
            ]
            WS=windows_size
            flag=1
            for i in tqdm(IDS):
                # print('i',i)
                smaller = df[df["ID"]==i]
                smaller=smaller.reset_index()
                del smaller["index"]
                # ts = các ID trùng nhau trừ đi IP đầu,ID 1  - ID 0, ID 2 - ID 0
                smaller["ts"]=smaller["ts"].values-smaller["ts"].values[0]
            
                for ii in f_list: # đặt tên và gán giá trị ví dụ ts_mean , ts_std
                    for jjj,iii in enumerate (func_ew):
                        name=str(ii)+"_"+str(func_name_ew[jjj])
                        smaller[name]=iii(smaller[ii])
                # có ID trùng nhau  >= WS mới tính sw
                if len(smaller)>=WS:
                    # tính toán giá trị dùng roll window
                    for ii in f_list:
                        for jjj,iii in enumerate (func_sw):
                            name=str(ii)+"_"+str(func_name_sw[jjj])
                            smaller[name]=iii(smaller[ii],WS)
                else:
                    for ii in fark:
                            smaller[ii]=0
                # smaller["dport_sum"]=portsum(smaller["dport"].values)
                # smaller["sport_sum"] =portsum(smaller["sport"].values)
                smaller['TCP_FIN_sum'  ]=flagsum (smaller[ 'TCP_FIN'  ].values)
                smaller['TCP_SYN_sum'  ]=flagsum (smaller['TCP_SYN'  ].values)
                smaller['TCP_RST_sum'  ]=flagsum (smaller['TCP_RST'  ].values)
                smaller['TCP_PSH_sum'  ]=flagsum (smaller['TCP_PSH'  ].values)
                smaller['TCP_ACK_sum'  ]=flagsum (smaller['TCP_ACK'  ].values)
                smaller['TCP_URG_sum'  ]=flagsum (smaller['TCP_URG'  ].values)
                smaller['TCP_ECE_sum'  ]=flagsum (smaller['TCP_ECE'  ].values)
                smaller['TCP_CWR_sum'  ]=flagsum (smaller['TCP_CWR'  ].values)
            
                smaller["TCP_SYN_ratio"]=smaller["TCP_SYN"]/(smaller["TCP_SYN_sum"]+10e-20)
            
                col_list= ["TCP_FIN_sum","TCP_SYN_sum","TCP_RST_sum","TCP_PSH_sum","TCP_ACK_sum","TCP_URG_sum","TCP_ECE_sum","TCP_CWR_sum"]
                smaller['sum'] = smaller[col_list].sum(axis=1)
    
                smaller["TCP_ACK_SR"]=smaller["TCP_ACK"]/(smaller["sum"]+10e-20)
                smaller["TCP_ACK_R"]=smaller["TCP_ACK_sum"]/(smaller["sum"]+10e-20)

                if flag:
                    smaller.to_csv(j[5:],header=True,index=False)
                    flag=0
                else:
                    smaller.to_csv(j[5:],header=False,index=False,mode="a")
            df=pd.read_csv(j[5:])
            features=df.columns
            count=[]
            bos=[]
            
            df=df.sort_values(by='Unnamed: 0')
        
            last_name=f'./{outputfolder}/last_{str(WS)}_{j[5:]}'
            df.to_csv(last_name,index=None)
            print(WS,"-------------------------------------------------------------------------------")
    # Merge SW files
    files_add=find_the_way('./SW','FE.csv')
    unique_file_names=[]
    for i in files_add:
        bas=i.replace('_', '@', 1).find('_')+1
        if i[bas:] not in unique_file_names:
            unique_file_names.append(i[bas:])
    for i in tqdm(unique_file_names):
        files_add=find_the_way('./SW',i)
        flag=1
        for ii in files_add:
            WS=ii.split("_")[1]
            print(WS)
            new_cols={'pck_size_mean':f'pck_size_mean_{WS}',
            'pck_size_std':f'pck_size_std_{WS}',
            'ts_mean':f'ts_mean_{WS}',
            'ts_std':f'ts_std_{WS}',
            'TCP_window_mean':f'TCP_window_mean_{WS}',
            'TCP_window_std':f'TCP_window_std_{WS}',
            }
            if flag:
                df=pd.read_csv(ii)
                df.rename(columns = new_cols, inplace = True)
                flag=0
            else:
                adding=pd.read_csv(ii,usecols=list(new_cols.keys()))
                adding.rename(columns = new_cols, inplace = True)
                df = pd.concat([df, adding], axis=1)
            os.remove(ii)
        temp=i.replace("_FE.","_SW.")
        temp=f"./SW/{temp}"
        df.to_csv(temp,index=False)
    # trong SW chỉ có 1 file unique nên lấy ra file đó
    predictFile=find_the_way('./SW','_SW.csv')
    print('predict file:',predictFile[0])
    df = pd.read_csv(predictFile[0],usecols=cols)#,header=None )
    df=df.fillna(0)
    X_test=df[cols]
    new_predictions = model.predict(X_test)
    for i in range(len(new_predictions)):
        if new_predictions[i]==1:
            print("Syn Flood")
    print('No of Syn Flood:',np.count_nonzero(new_predictions == 1))

if __name__ == "__main__":
    print("Starting real-time SYN Flood detection...")
    model = joblib.load("./model/RF_SYN_1_model.pkl")
    
    threading.Thread(target=packet_sniffer, daemon=True).start()
    threading.Thread(target=packet_processor, daemon=True).start()
    
    # Giữ chương trình chạy
    while True:
        pass

