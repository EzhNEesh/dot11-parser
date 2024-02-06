import re
import pandas as pd
from tabulate import tabulate

from frame_parser import crc_32_compare, validate_frame_subtype, is_drone


class Finder:
    def __init__(self):
        self.frames = pd.DataFrame()

    def parse_data(self, file_path: str):
        frames = {}
        with open(file_path, 'r') as file:
            for line in file:
                frame_data = line[11:].split(',')
                bits_buf = frame_data[4][5:-1]
                bits = [bits_buf[byte:byte+2] for byte in range(0, len(bits_buf), 2)]
                current_frame = {
                    'offset': frame_data[0][7:],
                    'BW': frame_data[1][3:],
                    'MCS': frame_data[2][4:],
                    'size': frame_data[3][5:],
                    'bits': bits
                }

                if crc_32_compare(bits):
                    current_frame['malformed'] = False
                    current_frame['crc'] = bits[-1] + bits[-2] + bits[-3] + bits[-4]
                    current_frame['subtype'] = validate_frame_subtype(bits[0])
                else:
                    current_frame['malformed'] = True
                frames[line[:10]] = current_frame
            self.frames = pd.DataFrame.from_dict(frames, orient='index')

    def search(self):
        for ind in self.frames[self.frames['subtype'] == 'Beacon'].index:
            ssid_length = self.frames.loc[ind, 'ssid_length'] = int(self.frames['bits'].loc[ind][37], 16)

            ssid = self.frames.loc[ind, 'ssid'] = bytes.fromhex(
                ''.join(
                    self.frames['bits'].loc[ind][38:38+ssid_length]
                )).decode('utf-8')

            is_drone_res = self.frames.loc[ind, 'is_drone'] = is_drone(ssid)

            if is_drone_res:
                self.frames.loc[ind, 'MAC_Source'] = ':'.join(self.frames['bits'].loc[ind][10:16])

    def save_to_file(self, file_path='results/drones_frames'):
        mac_addresses = self.frames[self.frames['is_drone'].notna()]['MAC_Source'].unique()
        with open(file_path, 'w') as file:
            for mac_address in mac_addresses:
                file.write(f'mac_address:\n')
                output_res = self.frames[self.frames['MAC_Source'] == mac_address][[
                    'offset',
                    'BW',
                    'MCS',
                    'size',
                    'ssid',
                    'MAC_Source'
                ]]
                file.write(tabulate(output_res, headers='keys', tablefmt='psql'))
                file.write('\n\n')


finder = Finder()
finder.parse_data('data/frames_phy.log')
finder.search()
finder.save_to_file()
