import pandas as pd
from tabulate import tabulate
import sys
from scapy.layers.dot11 import Dot11
import time

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

    def parse_data(self, file_path):
        frames = {}
        with open(file_path, 'r') as file:
            for line in file:
                frame_data = line[11:].split(',')
                bits_buf = frame_data[4][5:-1]
                bits = [bits_buf[byte:byte+2] for byte in range(0, len(bits_buf), 2)]

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
        for ind, row in self.frames.iterrows():
            self.frames.loc[ind, 'src_address'] = row['Dot11'].addr2
            self.frames.loc[ind, 'dst_address'] = row['Dot11'].addr1
            if (row['type'], row['subtype']) == (0, 8) or (row['type'], row['subtype']) == (0, 5):
                ssid = self.frames.loc[ind, 'ssid'] = row['Dot11'].info.decode("utf-8")
                if is_drone(ssid) or ssid == search_ssid:
                    self.frames.loc[ind, 'is_drone'] = True

                    # kok = set()
        # for ind in self.frames[self.frames['subtype'].apply(lambda x: x in (0, 1, 2, 3, 4, 5, 8, 9, 10, 11, 12, 13))].index:
        #     packet = self.frames.loc[ind, 'Dot11']
        #     kok.add((self.frames.loc[ind]['type'], self.frames.loc[ind]['subtype'], validate_frame_subtype(self.frames.loc[ind]['bits'][0])))
        # print(kok)
        # for ind in self.frames[(self.frames['subtype'] == 'Beacon') | (self.frames['subtype'] == 'Probe request')].index:
        #     ssid_length = self.frames.loc[ind, 'ssid_length'] = int(self.frames['bits'].loc[ind][37], 16)
        #     ssid = self.frames.loc[ind, 'ssid'] = hex_decoder(
        #         self.frames['bits'].loc[ind][38:38+ssid_length]
        #         )
        #
        #     is_drone_res = self.frames.loc[ind, 'is_drone'] = is_drone(ssid) + (search_ssid == ssid)
        #
        #     if is_drone_res:
        #         self.frames.loc[ind, 'MAC_Source'] = ':'.join(self.frames['bits'].loc[ind][10:16])

    def save_to_file(self, file_path='results/drones_frames'):
        mac_addresses = self.frames[self.frames['is_drone'].notna()]['src_address'].unique()
        with open(file_path, 'w') as file:
            for mac_address in mac_addresses:
                file.write('mac_address\n')
                # file.write(f'[{mac_address}]:\n')
                output_res = self.frames[self.frames['src_address'] == mac_address][[
                    'offset',
                    'BW',
                    'MCS',
                    'size',
                    'ssid',
                    'src_address',
                    'dst_address'
                ]]
                file.write(tabulate(output_res, headers='keys', tablefmt='psql'))
                file.write('\n\n')

        # with open(file_path + '_1', 'w') as file:
        #     for ind, row in self.frames.iterrows():
        #         print(row)
                # file.write(f'[{mac_address}]:\n')
                # output_res = self.frames[self.frames['MAC_Source'] == mac_address][[
                #     'offset',
                #     'BW',
                #     'MCS',
                #     'size',
                #     'ssid',
                #     'MAC_Source'
                # ]]

                # output_res = row[[
                #     'offset',
                #     'BW',
                #     'MCS',
                #     'size',
                #     'ssid',
                #     'MAC_Source'
                # ]]
                # file.write(tabulate(output_res, headers='keys', tablefmt='psql'))
                # file.write('\n\n')

time.sleep(10000)
argv_parser = SysArgvParser()
argv_results = argv_parser.parse_argv(sys.argv)
if argv_results[0]:
    print(argv_results[3])
    finder = Finder()
    finder.parse_data(argv_results[1])
    finder.search(argv_results[3])
    finder.save_to_file(argv_results[2])
