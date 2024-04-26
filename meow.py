# import pandas as pd
# from tabulate import tabulate
# import sys
# from scapy.layers.dot11 import Dot11
# from graph_visualisation.network_graph import NetworkGraph

# from frame_parser import crc_32_compare, validate_frame_subtype, is_drone, hex_decoder
#
# paths = ['data/frames_phy.log', 'data/mjx_bugs_12eis/frames_phy.log', 'data/walkera_aibao/frames_phy.log', 'data/xiaomi_fimi_mini/frames_phy.log']
#
# ignore_addreses = ['ff:ff:ff:ff:ff:ff', '80:4e:70:cb:be:78', 'b2:41:1d:32:ed:57', '86:29:3b:5f:c9:a7']
# drone_addresses = ['38:e2:6e:1a:69:ac', '38:e2:6e:22:78:fa', 'b0:41:1d:32:eb:dd', '6c:df:fb:e6:9a:4a']
#
# for path in paths[:3]:
#     frames = {}
#     with open(path, 'r') as file:
#         for line in file:
#             frame_data = line[11:].split(',')
#             bits_buf = frame_data[4][5:-1]
#             bits = [bits_buf[byte:byte + 2] for byte in range(0, len(bits_buf), 2)]
#
#             if crc_32_compare(bits):
#                 current_frame = {'offset': frame_data[0][7:],
#                                  'BW': frame_data[1][3:],
#                                  'MCS': frame_data[2][4:],
#                                  'size': frame_data[3][5:],
#                                  'bits': bits,
#                                  'crc': bits[-1] + bits[-2] + bits[-3] + bits[-4],
#                                  'type': Dot11(bytes.fromhex(bits_buf)).type,
#                                  'subtype': Dot11(bytes.fromhex(bits_buf)).subtype,
#                                  'Dot11': Dot11(bytes.fromhex(bits_buf))
#                                  }
#                 frames[line[:10]] = current_frame
#
#         frames_df = pd.DataFrame.from_dict(frames, orient='index')
#         for ind, row in frames_df.iterrows():
#             frames_df.loc[ind, 'src_address'] = src_address = row['Dot11'].addr2
#             frames_df.loc[ind, 'dst_address'] = dst_address = row['Dot11'].addr1
#             if (row['type'], row['subtype']) == (2, 8): #and src_address not in ignore_addreses and dst_address not in ignore_addreses and (src_address in drone_addresses or dst_address in drone_addresses) and src_address is not None and dst_address is not None:
#                 print(row['type'], row['subtype'])
#                 print('address: ', src_address)
#                 print('address: ', dst_address)
#                 print('=' * 10)
#     print('=' * 100)

from sklearn.neighbors import KNeighborsClassifier
import pandas as pd
from tabulate import tabulate
import sys
from scapy.layers.dot11 import Dot11
from graph_visualisation.network_graph import NetworkGraph
from collections import defaultdict

from frame_parser import crc_32_compare, validate_frame_subtype, is_drone, hex_decoder


def set_default():
    d = {}
    for i in range(15):
        d[(0, i)] = 0
    for i in range(16):
        d[(1, i)] = 0
        d[(2, i)] = 0
    for i in range(2):
        d[(3, i)] = 0
    return d

def set_zero():
    return 0


def get_mac_vector(d, k):
    vector = []
    for i in range(15):
        vector.append(d[(0, i)] / k)
    for i in range(16):
        vector.append(d[(1, i)] / k)
    for i in range(16):
        vector.append(d[(2, i)] / k)
    for i in range(2):
        vector.append(d[(3, i)] / k)
    return vector


train_data_dict = defaultdict(set_default)
train_results_ls = []
train_gen_frames_count = defaultdict(set_zero)

paths = ['data/frames_phy.log', 'data/mjx_bugs_12eis/frames_phy.log', 'data/xiaomi_fimi_mini/frames_phy.log', 'data/walkera_aibao/frames_phy.log']
drone_addresses = ['38:e2:6e:1a:69:ac', '38:e2:6e:22:78:fa', 'b0:41:1d:32:eb:dd', '6c:df:fb:e6:9a:4a']

for path in paths[:3]:
    frames = {}
    with open(path, 'r') as file:
        for line in file:
            frame_data = line[11:].split(',')
            bits_buf = frame_data[4][5:-1]
            bits = [bits_buf[byte:byte + 2] for byte in range(0, len(bits_buf), 2)]
            if crc_32_compare(bits):
                dot11 = Dot11(bytes.fromhex(bits_buf))
                ttype = Dot11(bytes.fromhex(bits_buf)).type
                subtype = Dot11(bytes.fromhex(bits_buf)).subtype
                mac = dot11.addr1
                if mac is not None:
                    train_data_dict[mac][(ttype, subtype)] += 1
                    train_gen_frames_count[mac] += 1

train_data_ls = []
for mac, vec in train_data_dict.items():
    train_data_ls.append(get_mac_vector(vec, train_gen_frames_count[mac]))
    if mac in drone_addresses:
        train_results_ls.append(1)
    else:
        train_results_ls.append(0)
#
test_data_dict = defaultdict(set_default)
test_results_ls = []
test_data_ls = []
test_gen_frames_count = defaultdict(set_zero)

with open(paths[-1], 'r') as file:
    for line in file:
        frame_data = line[11:].split(',')
        bits_buf = frame_data[4][5:-1]
        bits = [bits_buf[byte:byte + 2] for byte in range(0, len(bits_buf), 2)]
        if crc_32_compare(bits):
            dot11 = Dot11(bytes.fromhex(bits_buf))
            ttype = Dot11(bytes.fromhex(bits_buf)).type
            subtype = Dot11(bytes.fromhex(bits_buf)).subtype
            mac = dot11.addr1
            if mac is not None:
                test_data_dict[mac][(ttype, subtype)] += 1
                test_gen_frames_count[mac] += 1

for mac, vec in test_data_dict.items():
    test_data_ls.append(get_mac_vector(vec, test_gen_frames_count[mac]))
    if mac in drone_addresses:
        test_results_ls.append((mac, 1))
    else:
        test_results_ls.append((mac, 0))
# print(*test_data_ls, sep='\n')

for k in range(1, 10):
    mur = KNeighborsClassifier(n_neighbors=k)
    mur.fit(train_data_ls, train_results_ls)
    res = mur.predict(test_data_ls)
    for i in range(len(res)):
        print(test_results_ls[i], res[i])
    print('='*10)
