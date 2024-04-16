import pandas as pd
from tabulate import tabulate
import sys
from scapy.layers.dot11 import Dot11
from graph_visualisation.network_graph import NetworkGraph

from frame_parser import crc_32_compare, validate_frame_subtype, is_drone, hex_decoder


class SysArgvParser:
    def parse_argv(self, argv_list):
        if len(argv_list) < 2 or argv_list[1] in ['-h', '--help']:
            self.print_help()
            return [False]

        return_list = [True, 'data/frames_phy.log', 'results/drones_frames', ""]
        for i in range(2, len(argv_list), 2):
            if argv_list[i] in {'-o', '--output'}:
                return_list[2] = argv_list[i + 1]
            elif argv_list[i] in {'-s', '--ssid'}:
                return_list[3] = argv_list[i + 1]

        return return_list

    @staticmethod
    def print_help():
        print('Usage: python finder.py {INPUT FILE PATH} [OPTIONS]')
        print()
        print('Options:')
        print('-o, --output, path to output file')
        print('-s, --ssid, find a specific ssid')


class Finder:
    def __init__(self):
        self.frames = pd.DataFrame()
        self.suspicious_addresses = pd.DataFrame()
        self.drone_addresses = pd.DataFrame()

    def parse_data(self, file_path):
        frames = {}

        with open(file_path, 'r') as file:
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

            self.frames = pd.DataFrame.from_dict(frames, orient='index')

    def search(self, search_ssid):
        suspicious_addresses = []

        for ind, row in self.frames.iterrows():
            self.frames.loc[ind, 'src_address'] = src_address = row['Dot11'].addr2
            self.frames.loc[ind, 'dst_address'] = dst_address = row['Dot11'].addr1
            if (row['type'], row['subtype']) == (0, 8) or (row['type'], row['subtype']) == (0, 5):
                ssid = self.frames.loc[ind, 'ssid'] = row['Dot11'].info.decode("utf-8")
                if is_drone(ssid) or ssid == search_ssid:
                    self.frames.loc[ind, 'is_drone'] = True
                    suspicious_addresses.append({'address': src_address, 'ssid': ssid})
                    suspicious_addresses.append({'address': dst_address, 'ssid': ssid})

        self.suspicious_addresses = pd.DataFrame(suspicious_addresses)
        suspicious_addresses_grouped = (self.suspicious_addresses
                                        .groupby('ssid', as_index=False)
                                        .value_counts())
        idx = (suspicious_addresses_grouped.groupby(['ssid'])['count'].transform(max)
               == suspicious_addresses_grouped['count'])
        self.drone_addresses = suspicious_addresses_grouped[idx]

    def save_to_file(self, file_path='results/drones_frames'):
        with open(file_path, 'w') as file:
            for mac_address in self.drone_addresses['address']:
                file.write(f'{mac_address}\n')
                output_res = self.frames[
                    (self.frames['src_address'] == mac_address) | (self.frames['dst_address'] == mac_address)][
                    ['offset',
                     'BW',
                     'MCS',
                     'size',
                     'ssid',
                     'src_address',
                     'dst_address']]
                file.write(tabulate(output_res, headers='keys', tablefmt='psql'))
                file.write('\n\n')

    def draw_graph(self):
        ng = NetworkGraph()
        ng.draw_graph(self.frames[['src_address', 'dst_address', 'is_drone']], self.drone_addresses)


argv_parser = SysArgvParser()
argv_results = argv_parser.parse_argv(sys.argv)
if argv_results[0]:
    finder = Finder()
    finder.parse_data(argv_results[1])
    finder.search(argv_results[3])
    finder.save_to_file(argv_results[2])
    finder.draw_graph()
