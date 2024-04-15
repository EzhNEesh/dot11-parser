import networkx as nx
import matplotlib.pyplot as plt


class NetworkGraph:
    graph = nx.Graph()

    def draw_graph(self, network_points, drone_addresses):
        for ind, row in network_points.iterrows():
            if row['src_address'] is not None and row['dst_address'] is not None:
                if isinstance(row['is_drone'], bool) and row['is_drone']:
                    self.graph.add_edge(row['src_address'], row['dst_address'])
                else:
                    self.graph.add_edge(row['src_address'], row['dst_address'])
        color_map = ['red' if node in drone_addresses['address'].values else 'green' for node in self.graph]
        # pos = nx.spectral_layout(self.graph)
        nx.draw(self.graph, node_color=color_map, with_labels=True)
        plt.show()
