from scapy.layers.dot11 import Dot11
import pandas as pd
import numpy as np
from sklearn.preprocessing import MinMaxScaler

from src.networking.crc32 import crc_32_compare


class Dot11DataFrame:
    def __init__(self):
        self.frames = pd.DataFrame()
        # self.vectors = np.array([])
        # self.macs = []

    @staticmethod
    def line_process(line):
        frame_data = line[11:].split(',')
        bits = frame_data[4][5:-1]
        bits_split = [bits[byte:byte + 2] for byte in range(0, len(bits), 2)]
        return frame_data, bits, bits_split, crc_32_compare(bits_split)

    def from_file(self, file_path):
        frames = {}
        with open(file_path, 'r') as file:
            for line in file:
                frame_data, bits, bits_split, crc32_verified = self.line_process(line)
                if crc32_verified:
                    dot11 = Dot11(bytes.fromhex(bits))
                    frames[line[:10]] = {
                        'offset': frame_data[0][7:],
                        'BW': int(frame_data[1][3:5]),
                        'MCS': frame_data[2][4:],
                        'size': int(frame_data[3][5:]),
                        'bits': bits_split,
                        'crc': bits_split[-1] + bits_split[-2] + bits_split[-3] + bits_split[-4],
                        'type': dot11.type,
                        'subtype': dot11.subtype,
                        'is_QoS': (dot11.type, dot11.subtype) == (2, 8),
                        'to_ds': dot11.FCfield & 0x1 != 0,
                        'from_ds': dot11.FCfield & 0x2 != 0,
                        'more_frame': dot11.FCfield & 0x3 != 0,
                        'retry': dot11.FCfield & 0x4 != 0,
                        'protected': dot11.FCfield & 0x7 != 0,
                        'order': dot11.FCfield & 0x8 != 0,  # +HTC/order(+-)
                        'Dot11': dot11,
                        'src_address': dot11.addr2,
                        'dst_address': dot11.addr1,
                    }
        self.frames = pd.DataFrame.from_dict(frames, orient='index')

    def get_frames_contacts_with(self, mac):
        return self.frames[self.frames.src_address == mac]

    def get_control_devices(self, drone_addresses):
        control_devices = []
        for drone_address in drone_addresses:
            control_devices.append(
                self.get_frames_contacts_with(drone_address)  # data/walkera_aibao/frames_phy.log
                .groupby('dst_address')
                .size()
                .reset_index(name='counts')
                .sort_values('counts', ascending=False)
                .head(1)
                .iloc[0]
                ['dst_address']
            )

        return control_devices

    def get_drones_by_ssid(self, ssid):
        macs = []
        for ind, frame in self.frames.iterrows():
            if frame['type'] == 0 and frame['subtype'] == 8 and frame['Dot11'].info.decode("utf-8") == ssid:
                macs.append(frame['src_address'])
        return macs

    def get_frames_by_mac(self, mac):
        return self.frames[(self.frames['src_address'] == mac) | (self.frames['dst_address'] == mac)]

    @staticmethod
    def get_macs_by_prediction(prediction, macs):
        result = []
        for i, val in enumerate(prediction):
            if val:
                result.append(macs[i])
        return result

    @staticmethod
    def read_macs_from_file(filepath):
        macs = []
        with open(filepath, 'r') as file:
            for line in file:
                macs.append(line.strip('\n'))
        return macs


class Vectorizer:
    @staticmethod
    def vectorize_frame(device_vectors):
        vector = device_vectors[[
            'is_QoS',  # BW / 40
            'to_ds', 'from_ds',
            'more_frame', 'retry',
            'protected', 'order']].mean().values
        vector = np.append(vector, 0 < sum((device_vectors['type'] == 0) & (device_vectors['subtype'] == 8)))
        return vector

    def vectorize_frames(self, dot11_frames):
        scaler = MinMaxScaler()
        vectors = []
        macs = []
        for mac, group in dot11_frames.frames.groupby(['src_address']):
            vector = self.vectorize_frame(group)
            vectors.append(vector)
            macs.append(mac[0])
        # vectors_std = np.array(vectors)
        # scaler.fit(vectors_std)
        scaler = MinMaxScaler()
        scaler.fit(vectors)
        vectors = scaler.transform(vectors)

        macs = macs
        return vectors, macs
