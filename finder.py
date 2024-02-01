from frame_parser import crc_32_compare, validate_frame_subtype
import re


class Finder:
    def __init__(self):
        self.frames = {}
        self.frames_unvalidated = {}
        self.frames_malformed = {}

    def parse_data(self, file_path: str):
        with open(file_path) as file:
            for line in file:
                frame_data = line[11:].split(',')
                bits_buf = frame_data[4][5:-1]
                bits = [bits_buf[byte:byte+2] for byte in range(0, len(bits_buf), 2)]

                if crc_32_compare(bits):
                    current_frame = {
                        'offset': frame_data[0][7:],
                        'BW': frame_data[1][3:],
                        'MCS': frame_data[2][4:],
                        'size': frame_data[3][5:],
                        'bits': bits,
                        'crc': bits[-1] + bits[-2] + bits[-3] + bits[-4],
                        'subtype': validate_frame_subtype(bits[0])
                    }
                    if current_frame['subtype'] == 'Beacon':
                        self.frames[line[:10]] = current_frame
                    else:
                        self.frames_unvalidated[line[:10]] = current_frame
                else:
                    current_frame = {
                        'offset': frame_data[0][7:],
                        'BW': frame_data[1][3:],
                        'MCS': frame_data[2][4:],
                        'size': frame_data[3][5:],
                        'bits': bits
                    }
                    self.frames_malformed[line[:10]] = current_frame

    def search(self):
        for ind, frame in self.frames.items():
            ssid_length = int(frame['bits'][37], 16)
            ssid = ''.join(frame['bits'][38:38 + ssid_length])
            ssid_str = bytes.fromhex(ssid).decode('utf-8')
            res = re.search('.*drone.*', ssid_str.lower())
            if res:
                print(res[0])


finder = Finder()
finder.parse_data('data/frames_phy.log')
finder.search()
