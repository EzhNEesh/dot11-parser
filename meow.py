# import pandas as pd
# from tabulate import tabulate
# import sys
# from scapy.layers.dot11 import Dot11
# from graph_visualisation.network_graph import NetworkGraph

# from networking import crc_32_compare, validate_frame_subtype, is_drone, hex_decoder
#
# paths = ['data/frames_phy.log', 'data/mjx_bugs_12eis/frames_phy.log', 'data/walkera_aibao/frames_phy.log', 'data/xiaomi_fimi_mini/frames_phy.log']
#
# ignore_addreses = ['ff:ff:ff:ff:ff:ff', '80:4e:70:cb:be:78', 'b2:41:1d:32:ed:57', '86:29:3b:5f:c9:a7']
# drone_addresses = ['38:e2:6e:1a:69:ac', '38:e2:6e:22:78:fa', 'b0:41:1d:32:eb:dd', '6c:df:fb:e6:9a:4a']
#
# data/frames_phy.log
# data/mjx_bugs_12eis/frames_phy.log
# data/xiaomi_fimi_mini/frames_phy.log
#
# 38:e2:6e:1a:69:ac
# 38:e2:6e:22:78:fa
# b0:41:1d:32:eb:dd
# 6c:df:fb:e6:9a:4a
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
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from scapy.layers.dot11 import Dot11
import numpy as np

from src.networking import crc_32_compare


# import pylab as pl
# from matplotlib.colors import ListedColormap


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


def get_mac_vector(mac_vectors):
    vector = np.mean(mac_vectors[:, [0, 3, 4, 5, 6, 7, 8]], axis=0)
    vector = np.append(vector, ((0, 8) in map(lambda x: tuple(x), mac_vectors[:, 1:3])))  # mac is access point
    # vector = np.array([([0, 8] in mac_vectors[:, [0, 1]]) * 10000])
    return vector


train_data_dict = dict()  # defaultdict(lambda: np.zeros(8))
train_data_ls = []
train_results_ls = []

paths = ['data/frames_phy.log', 'data/mjx_bugs_12eis/frames_phy.log', 'data/xiaomi_fimi_mini/frames_phy.log', 'data/walkera_aibao/frames_phy.log']
drone_addresses = ['38:e2:6e:1a:69:ac', '38:e2:6e:22:78:fa', 'b0:41:1d:32:eb:dd', '6c:df:fb:e6:9a:4a']

for path in paths[:-1]:
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
                mac = dot11.addr2
                if mac is not None:
                    if mac not in train_data_dict:
                        train_data_dict[mac] = np.array([[
                            (ttype, subtype) == (2, 8),  # frame subtype is QoS data
                            ttype,
                            subtype,
                            dot11.FCfield & 0x1 != 0,  # to-ds
                            dot11.FCfield & 0x2 != 0,  # from-ds
                            dot11.FCfield & 0x3 != 0,  # more frame
                            dot11.FCfield & 0x4 != 0,  # retry
                            dot11.FCfield & 0x7 != 0,  # protected
                            dot11.FCfield & 0x8 != 0,  # +HTC/order(+-)
                            ]])
                    else:
                        train_data_dict[mac] = np.append(
                            train_data_dict[mac],
                            [[
                                (ttype, subtype) == (2, 8),  # frame subtype is QoS data
                                ttype,
                                subtype,
                                dot11.FCfield & 0x1 != 0,  # to-ds
                                dot11.FCfield & 0x2 != 0,  # from-ds
                                dot11.FCfield & 0x3 != 0,  # more frame
                                dot11.FCfield & 0x4 != 0,  # retry
                                dot11.FCfield & 0x7 != 0,  # protected
                                dot11.FCfield & 0x8 != 0,  # +HTC/order(+-)
                                ]],
                            axis=0)

# print([0,8] in train_data_dict['38:e2:6e:1a:69:ac'][:, [0, 1]])
# print(train_data_dict)
for mac, vectors in train_data_dict.items():
    train_data_ls.append(get_mac_vector(vectors))
    if mac in drone_addresses:
        train_results_ls.append(1)
    else:
        train_results_ls.append(0)
# print(train_data_ls)


test_data_dict = dict()  # defaultdict(partial(np.array, 0))
test_results_ls = []
test_data_ls = []
# test_gen_frames_count = defaultdict(set_zero)

with open(paths[-1], 'r') as file:
    for line in file:
        frame_data = line[11:].split(',')
        bits_buf = frame_data[4][5:-1]
        bits = [bits_buf[byte:byte + 2] for byte in range(0, len(bits_buf), 2)]
        if crc_32_compare(bits):
            dot11 = Dot11(bytes.fromhex(bits_buf))
            ttype = Dot11(bytes.fromhex(bits_buf)).type
            subtype = Dot11(bytes.fromhex(bits_buf)).subtype
            mac = dot11.addr2
            if mac is not None:
                if mac not in test_data_dict:
                    test_data_dict[mac] = np.array([[
                        (ttype, subtype) == (2, 8),  # frame subtype is QoS data
                        ttype,
                        subtype,
                        dot11.FCfield & 0x1 != 0,  # to-ds
                        dot11.FCfield & 0x2 != 0,  # from-ds
                        dot11.FCfield & 0x3 != 0,  # more frame
                        dot11.FCfield & 0x4 != 0,  # retry
                        dot11.FCfield & 0x7 != 0,  # protected
                        dot11.FCfield & 0x8 != 0,  # +HTC/order(+-)
                        ]])
                else:
                    test_data_dict[mac] = np.append(
                        test_data_dict[mac],
                        [[
                            (ttype, subtype) == (2, 8),  # frame subtype is QoS data
                            ttype,
                            subtype,
                            dot11.FCfield & 0x1 != 0,  # to-ds
                            dot11.FCfield & 0x2 != 0,  # from-ds
                            dot11.FCfield & 0x3 != 0,  # more frame
                            dot11.FCfield & 0x4 != 0,  # retry
                            dot11.FCfield & 0x7 != 0,  # protected
                            dot11.FCfield & 0x8 != 0,  # +HTC/order(+-)
                            ]],
                        axis=0)

for mac, vectors in test_data_dict.items():
    test_data_ls.append(get_mac_vector(vectors))
    if mac in drone_addresses:
        test_results_ls.append((mac, 1))
    else:
        test_results_ls.append((mac, 0))
    # for vec in vectors:
    #     if tuple(vec[:2]) == (0, 8):
    #         print(mac, vec)
# print(*test_data_ls, sep='\n')

print('KNN: ')
for k in range(1, 5):
    mur = KNeighborsClassifier(n_neighbors=k)
    mur.fit(train_data_ls, train_results_ls)
    res = mur.predict(test_data_ls)
    for i in range(len(res)):
        print(test_results_ls[i], res[i])
    print('='*10)

print('Logistic regression: ')
log_reg = LogisticRegression(random_state=0).fit(train_data_ls, train_results_ls)
res = log_reg.predict(test_data_ls)
for i in range(len(res)):
    print(test_results_ls[i], res[i])
print('=' * 10)

print('Decision tree: ')
dec_tree = DecisionTreeClassifier().fit(train_data_ls, train_results_ls)
res = dec_tree.predict(test_data_ls)
for i in range(len(res)):
    print(test_results_ls[i], res[i])
print('=' * 10)

# def set_default():
#     d = {}
#     for i in range(15):
#         d[(0, i)] = 0
#     for i in range(16):
#         d[(1, i)] = 0
#         d[(2, i)] = 0
#     for i in range(2):
#         d[(3, i)] = 0
#     return d
#
# def set_zero():
#     return 0
#
#
# def get_mac_vector(d, k):
#     vector = []
#     for i in range(15):
#         vector.append(d[(0, i)] / k)
#     for i in range(16):
#         vector.append(d[(1, i)] / k)
#     for i in range(16):
#         vector.append(d[(2, i)] / k)
#     for i in range(2):
#         vector.append(d[(3, i)] / k)
#     return vector
#
#
# train_data_dict = defaultdict(set_default)
# train_results_ls = []
# train_gen_frames_count = defaultdict(set_zero)
#
# paths = ['data/frames_phy.log', 'data/mjx_bugs_12eis/frames_phy.log', 'data/xiaomi_fimi_mini/frames_phy.log', 'data/walkera_aibao/frames_phy.log']
# drone_addresses = ['38:e2:6e:1a:69:ac', '38:e2:6e:22:78:fa', 'b0:41:1d:32:eb:dd', '6c:df:fb:e6:9a:4a']
#
# for path in paths[:3]:
#     frames = {}
#     with open(path, 'r') as file:
#         for line in file:
#             frame_data = line[11:].split(',')
#             bits_buf = frame_data[4][5:-1]
#             bits = [bits_buf[byte:byte + 2] for byte in range(0, len(bits_buf), 2)]
#             if crc_32_compare(bits):
#                 dot11 = Dot11(bytes.fromhex(bits_buf))
#                 ttype = Dot11(bytes.fromhex(bits_buf)).type
#                 subtype = Dot11(bytes.fromhex(bits_buf)).subtype
#                 mac = dot11.addr1
#                 if mac is not None:
#                     train_data_dict[mac][(ttype, subtype)] += 1
#                     train_gen_frames_count[mac] += 1
#
# train_data_ls = []
# for mac, vec in train_data_dict.items():
#     train_data_ls.append(get_mac_vector(vec, train_gen_frames_count[mac]))
#     if mac in drone_addresses:
#         train_results_ls.append(1)
#     else:
#         train_results_ls.append(0)
# #
# test_data_dict = defaultdict(set_default)
# test_results_ls = []
# test_data_ls = []
# test_gen_frames_count = defaultdict(set_zero)
#
# with open(paths[-1], 'r') as file:
#     for line in file:
#         frame_data = line[11:].split(',')
#         bits_buf = frame_data[4][5:-1]
#         bits = [bits_buf[byte:byte + 2] for byte in range(0, len(bits_buf), 2)]
#         if crc_32_compare(bits):
#             dot11 = Dot11(bytes.fromhex(bits_buf))
#             ttype = Dot11(bytes.fromhex(bits_buf)).type
#             subtype = Dot11(bytes.fromhex(bits_buf)).subtype
#             mac = dot11.addr1
#             if mac is not None:
#                 test_data_dict[mac][(ttype, subtype)] += 1
#                 test_gen_frames_count[mac] += 1
#
# for mac, vec in test_data_dict.items():
#     test_data_ls.append(get_mac_vector(vec, test_gen_frames_count[mac]))
#     if mac in drone_addresses:
#         test_results_ls.append((mac, 1))
#     else:
#         test_results_ls.append((mac, 0))
# # print(*test_data_ls, sep='\n')
#
#
# mur = KNeighborsClassifier()
# mur.fit(train_data_ls, train_results_ls)
# test_results_ls = mur.predict(test_data_ls)



# from sklearn.decomposition import PCA
# import matplotlib.pyplot as plt
#
# # Объедините обучающие и тестовые данные для выполнения PCA на всем наборе данных
# all_data = train_data_ls + test_data_ls
#
# # Примените PCA для понижения размерности до 2 компонент
# pca = PCA(n_components=2)
# pca_result = pca.fit_transform(all_data)
#
# # Разделите данные обратно на обучающие и тестовые
# train_pca_result = pca_result[:len(train_data_ls)]
# test_pca_result = pca_result[len(train_data_ls):]
#
# # Постройте график для обучающих данных
# plt.scatter(train_pca_result[:, 0], train_pca_result[:, 1], label='Train Data')
# # Добавьте график для тестовых данных, если они есть
# if len(test_data_ls) > 0:
#     plt.scatter(test_pca_result[:, 0], test_pca_result[:, 1], label='Test Data', marker='x')
#
# plt.title('PCA Plot of Data')
# plt.xlabel('Principal Component 1')
# plt.ylabel('Principal Component 2')
# plt.legend()
# plt.show()

# from sklearn.decomposition import PCA
# import matplotlib.pyplot as plt
#
# # Объедините обучающие и тестовые данные для выполнения PCA на всем наборе данных
# all_data = train_data_ls + test_data_ls
#
# # Примените PCA для понижения размерности до 2 компонент
# pca = PCA(n_components=2)
# pca_result = pca.fit_transform(all_data)
#
# # Разделите данные обратно на обучающие и тестовые
# train_pca_result = pca_result[:len(train_data_ls)]
# test_pca_result = pca_result[len(train_data_ls):]
#
# # Получите индексы train_results_ls, которые равны 1
# index_ones = [i for i, result in enumerate(train_results_ls) if result == 1]
#
# # Разделите train_pca_result на два подмножества: одно для результатов равных 1, другое для остальных результатов
# train_pca_result_ones = train_pca_result[index_ones]
# train_pca_result_others = [train_pca_result[i] for i in range(len(train_pca_result)) if i not in index_ones]
#
# # Постройте график для обучающих данных, разделенных по результатам
# plt.scatter([point[0] for point in train_pca_result_others], [point[1] for point in train_pca_result_others], label='Train Data (Other)')
# plt.scatter([point[0] for point in train_pca_result_ones], [point[1] for point in train_pca_result_ones], label='Train Data (Result=1)', color='red')
# # Добавьте график для тестовых данных, если они есть
#
# index_ones = [i for i, result in enumerate(test_results_ls) if result == 1]
# test_pca_result_ones = test_pca_result[index_ones]
# test_pca_result_others = [test_pca_result[i] for i in range(len(test_pca_result)) if i not in index_ones]
#
# if len(test_data_ls) > 0:
#     plt.scatter([point[0] for point in test_pca_result_others], [point[1] for point in test_pca_result_others], label='Test Data (Other)', marker='x')
#     plt.scatter([point[0] for point in test_pca_result_ones], [point[1] for point in test_pca_result_ones], label='Test Data (Result=1)', marker='x', color='green')
#     # plt.scatter(test_pca_result[:, 0], test_pca_result[:, 1], label='Test Data', marker='x')
#
# plt.title('PCA Plot of Data')
# plt.xlabel('Principal Component 1')
# plt.ylabel('Principal Component 2')
# plt.legend()
# plt.show()


# for k in range(1, 10):
#     mur = KNeighborsClassifier(n_neighbors=k)
#     mur.fit(train_data_ls, train_results_ls)
#     res = mur.predict(test_data_ls)
#     for i in range(len(res)):
#         print(test_results_ls[i], res[i])
#     print('='*10)
