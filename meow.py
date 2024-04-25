import pandas as pd
from tabulate import tabulate
import sys
from scapy.layers.dot11 import Dot11
from graph_visualisation.network_graph import NetworkGraph

from frame_parser import crc_32_compare, validate_frame_subtype, is_drone, hex_decoder

paths = ['data/frames_phy.log', 'data/mjx_bugs_12eis/frames_phy.log', 'data/walkera_aibao/frames_phy.log', 'data/xiaomi_fimi_mini/frames_phy.log']

ignore_addreses = ['ff:ff:ff:ff:ff:ff', '80:4e:70:cb:be:78', 'b2:41:1d:32:ed:57', '86:29:3b:5f:c9:a7']
drone_addresses = ['38:e2:6e:1a:69:ac', '38:e2:6e:22:78:fa', 'b0:41:1d:32:eb:dd', '6c:df:fb:e6:9a:4a']

for path in paths[:3]:
    frames = {}
    with open(path, 'r') as file:
        for line in file:
            frame_data = line[11:].split(',')
            bits_buf = frame_data[4][5:-1]
            bits = [bits_buf[byte:byte + 2] for byte in range(0, len(bits_buf), 2)]

            if crc_32_compare(bits):
                current_frame = {'offset': frame_data[0][7:],
                                 'BW': frame_data[1][3:],
                                 'MCS': frame_data[2][4:],
                                 'size': frame_data[3][5:],
                                 'bits': bits,
                                 'crc': bits[-1] + bits[-2] + bits[-3] + bits[-4],
                                 'type': Dot11(bytes.fromhex(bits_buf)).type,
                                 'subtype': Dot11(bytes.fromhex(bits_buf)).subtype,
                                 'Dot11': Dot11(bytes.fromhex(bits_buf))
                                 }
                frames[line[:10]] = current_frame

        frames_df = pd.DataFrame.from_dict(frames, orient='index')
        for ind, row in frames_df.iterrows():
            frames_df.loc[ind, 'src_address'] = src_address = row['Dot11'].addr2
            frames_df.loc[ind, 'dst_address'] = dst_address = row['Dot11'].addr1
            if (row['type'], row['subtype']) == (2, 8): #and src_address not in ignore_addreses and dst_address not in ignore_addreses and (src_address in drone_addresses or dst_address in drone_addresses) and src_address is not None and dst_address is not None:
                print(row['type'], row['subtype'])
                print('address: ', src_address)
                print('address: ', dst_address)
                print('=' * 10)
    print('=' * 100)

