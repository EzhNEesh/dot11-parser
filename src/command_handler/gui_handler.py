from ..networking.dot11_frames import Dot11DataFrame, Vectorizer
from ..ml_models.models import ModelManager
from tabulate import tabulate

import numpy as np


class Handler:
    @staticmethod
    def read_frames(path):
        dot11_dataframe = Dot11DataFrame()
        dot11_dataframe.from_file(path)
        return dot11_dataframe

    @staticmethod
    def predict(model_name, dot11_dataframe):
        model = ModelManager.get_model(model_name)
        vectors, macs = Vectorizer().vectorize_frames(dot11_dataframe)
        prediction = model.predict(vectors)

        drone_addresses = dot11_dataframe.get_macs_by_prediction(prediction, macs)
        control_devices = dot11_dataframe.get_control_devices(drone_addresses)

        return prediction, macs, control_devices

    @staticmethod
    def get_drones_by_ssid(dot11_dataframe, ssid):
        macs = dot11_dataframe.get_drones_by_ssid(ssid)
        control_devices = dot11_dataframe.get_control_devices(macs)
        return macs, control_devices

    def retrain_model(self, model_name, paths_to_datas, drones_addresses):
        train_data = np.empty((0, 8), int)
        mac_addresses = np.empty((0, 1), int)
        for path in paths_to_datas[:-1]:
            dot11_dataframe = self.read_frames(path)
            vectors, macs = Vectorizer().vectorize_frames(dot11_dataframe)
            train_data = np.append(train_data, np.array(vectors), axis=0)
            mac_addresses = np.append(mac_addresses, macs)

        train_results = np.empty((0, 1), int)
        for mac in mac_addresses:
            train_results = np.append(train_results, mac in drones_addresses)
        ModelManager().retrain_model(model_name, train_data, train_results)

    @staticmethod
    def save_to_file(dot11_dataframe, macs, path='results/report'):
        with open(path, 'w') as file:
            for mac_address in macs:
                file.write(f'{mac_address}\n')
                output_frames = dot11_dataframe.get_frames_by_mac(mac_address)
                output_res = output_frames[
                    ['offset',
                     'BW',
                     'MCS',
                     'size',
                     'src_address',
                     'dst_address']]
                file.write(tabulate(output_res, headers='keys', tablefmt='psql'))
                file.write('\n\n')
