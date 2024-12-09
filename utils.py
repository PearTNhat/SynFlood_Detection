import zipfile
import os
import time
import shutil
import pandas as pd
from tqdm import tqdm
import pandas as pd
import warnings
warnings.filterwarnings("ignore")
#flags
#TCP
cols =[
        "ts", #Time Stamp
        "IP_flags", #IP fragmentation
        "IP_DF", #IP Don’t Fragment
        "TCP_dataofs", #TCP data ofset
        "TCP_SYN", #Sync Flag
        "TCP_ACK", #Acknowledgment Flag
        "sport_class", #Source Port Class (IoTDevID classing)
        "dst_IP_diversity",  #Number of Destination IP (by Source IP)
        "dst_port_diversity",#Number of Destination Port (by Source IP)
        "pck_size_sum_of_EW", #EW packet size total.
        "ts_diff", #he time difference of consecutive packets
        "ts_std_WE", #EW packet time Std.
        "ts_sum_of_EW", #EW packet time total.
        "TCP_window_std_WE", #EW TCP Windows size Std.
        "pck_size_mean_2",  #RW (Rolling windows) packet size mean
        "ts_mean_2", #RW packet time mean - Window size =2
        "ts_std_2", #RW packet time Std.- Window size =2
        "TCP_window_mean_2", #RW TCP Windows size mean - Window size =2
        "TCP_SYN_sum", #Number of TCP Sync Flag
        "TCP_ACK_sum", #EW Acknowledgment Flag
        "TCP_SYN_ratio", #TCP_SYN/TCP_SYN_sum
        "TCP_ACK_SR", #TCP_ACK/sum
        "ts_mean_6",#RW packet time mean - Window size =6
        "ts_std_6",#RW packet time Std.- Window size =6
        "pck_size_mean_9",#	RW (Rolling windows) packet size mean - Window size =9
        "ts_mean_9",#RW packet time mean - Window size =9
        "ts_std_9",#RW packet time Std.- Window size =9
        "TCP_window_mean_9",#RW TCP Windows size mean - Window size =9	
        "TCP_ACK_R",#TCP_ACK_sum/sum
        # "Label"
]
def folder(f_name): #this function creates a folder named "attacks" in the program directory.
    try:
        if not os.path.exists(f_name):
            os.makedirs(f_name)
    except OSError:
        print ("The folder could not be created!")

def find_the_way(path,file_format,con=""):
    files_add = []
    # r=root, d=directories, f = files
    for r, d, f in os.walk(path):
        for file in f:
            if file_format in file:
                if con in file:
                    files_add.append(os.path.join(r, file))  
    return files_add
def port_class(port):
    port_list=[0,53,67,68,80,123,443,1900,5353,49153]# private port list (0-Reserved,53-DNS, 67-BOOTP server, 68-BOOTP client...)
    if port in port_list: #Is the port number in the list?
        return port_list.index(port)+1 # return the port's index number in the list (actually with index+1)
    elif 0 <= port <= 1023: # return 11 if the port number is in the range 0 :1023
        return 11
    elif  1024 <= port <= 49151 : # return 12 if the port number is in the range 1024:49151
        return 12
    elif 49152 <=port <= 65535 :# return 13 if the port number is in the range 49152:65535
        return 13
    else:# return 0 if no previous conditions are met
        return 0
def flag_fixer(file):

    IP_flags={
    '0': 1,
    '<Flag 0 ()>': 2,
    '<Flag 2 (DF)>': 3,
    '<Flag 1 (MF)>': 4,
    '<Flag 3 (MF+DF)>': 40,
    '<Flag 4 (evil)>': 41,
    '<Flag 5 (MF+evil)>': 42,
    '<Flag 6 (DF+evil)>': 43,
    '<Flag 7 (MF+DF+evil)>': 44,
    '': 2,
    'DF': 3,
    'MF': 4,
    'MF+DF': 40,
    'evil': 41,
    'MF+evil': 42,
    'DF+evil)': 43,
    'MF+DF+evil)': 44
    }
    df=pd.read_csv(file)
    IP_flags
    df["IP_flags"]=df["IP_flags"].map(IP_flags.get)
    df.to_csv(file,index=None)
    
    df.to_csv(file,index=None)
def merged_csv(name,keyword):
    for merger in ["_FE.csv","_WS.csv"]:
        merged_name=f"{name[:-4]}{merger}"
        csv_files=find_the_way("./",keyword,merger)
        df=pd.read_csv(csv_files[0])
        col_names=list(df.columns)
        empty = pd.DataFrame(columns=col_names)
        empty.to_csv(merged_name, mode="w", index=False)#,header=False)
        for j in csv_files:
            df=pd.read_csv(j)
            #print("name and shape of dataframe :",i,df.shape)
            df.to_csv(merged_name, mode="a", index=False,header=False)
            os.remove(j)
            try:
                os.remove(j.replace("_FE.csv",".pcap"))
            except:pass
def folder(f_name): #this function creates a folder.
    try:
        if not os.path.exists(f_name):
            os.makedirs(f_name)
    except OSError:
        print ("The folder could not be created!")
        
# Tính hiệu số giữa các giá trị liên tiếp trong danh sách x.
def diff(x):
    x = pd.Series(x)
    result=x.diff()
    result=result.fillna(0)
    return result
# Tính giá trị trung bình di động (rolling mean) với kích thước cửa sổ WS
# Trả về danh sách trung bình di động.
def mean(x,WS):
    x = pd.Series(x)
    result=x.rolling(WS).mean()
    result=result.fillna(result[WS-1])
    return result
# Tính độ lệch chuẩn di động (rolling standard deviation) với kích thước cửa sổ WS
# Tương tự hàm mean(x, WS), nhưng tính độ lệch chuẩn thay vì trung bình.
def std(x,WS):
    x = pd.Series(x)
    result=x.rolling(WS).std()
    result=result.fillna(result[WS-1])
    return result
# Tính trung bình mở rộng (expanding mean) cho tất cả giá trị từ đầu đến vị trí hiện tại.
# Trả về danh sách trung bình mở rộng.
def mean_EW(x):
    x = pd.Series(x)
    result=x.expanding(min_periods=1).mean()
    return result
# Tính độ lệch chuẩn mở rộng (expanding standard deviation).
def std_EW(x):
    x = pd.Series(x)
    result=x.expanding(min_periods=1).std() # Tính độ lệch chuẩn cho tất cả giá trị từ đầu đến vị trí hiện tại.
    result=result.fillna(0)
    return result
# Tính tổng mở rộng (expanding sum).
# Tương tự mean_EW(x), nhưng tính tổng thay vì trung bình.
def sum_of_EW(x):
    x = pd.Series(x)
    result=x.expanding(min_periods=1).sum()
    return result
# Tính phương sai di động (rolling variance) với kích thước cửa sổ WS.
def var(x,WS):
    x = pd.Series(x)
    result=x.rolling(WS).var()
    result=result.fillna(result[WS-1])
    return result
# Tính tổng tích lũy cho các giá trị 1 trong danh sách x.
# Trả về danh sách với tổng tích lũy của các giá trị 1.
def flagsum(x):
    total_f=0
    result=[]
    for i in x:
        if i==1:
            total_f+=1
        result.append(total_f)
    return result
# Tính số lượng cổng (port) duy nhất đã xuất hiện trong danh sách x tính đến từng thời điểm.
# Trả về danh sách số lượng cổng duy nhất.
def portsum(x):
    total_ports=[]
    result=[]
    for i in x:
        if i not in total_ports:
            total_ports.append(i)
        result.append(len(total_ports))
    return result     