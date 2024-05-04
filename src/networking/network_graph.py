import networkx as nx
import matplotlib.pyplot as plt


class NetworkGraph:
    graph = nx.Graph()

    def draw_graph(self, dot11_dataframe, prediction, macs, control_devices):
        for ind, row in dot11_dataframe.frames.iterrows():
            if row['src_address'] is not None and row['dst_address'] is not None:
                self.graph.add_edge(row['src_address'], row['dst_address'])
        drones_macs = dot11_dataframe.get_macs_by_prediction(prediction, macs)

        color_map = []
        for node in self.graph:
            if node in drones_macs:
                color_map.append('red')
            elif node in control_devices:
                color_map.append('orange')
            else:
                color_map.append('green')
            # color_map = ['red' if node in drones_macs else 'green' for node in self.graph]
        # pos = nx.spectral_layout(self.graph)
        nx.draw(self.graph, node_color=color_map, with_labels=True)
        plt.show()
