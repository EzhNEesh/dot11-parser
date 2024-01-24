class Finder:
    def __init__(self):
        self.frame_data = []

    def parse_data(self, file_path: str):
        with open(file_path) as file:
            for line in file:
                meta = line[11:].split(',')
                current_frame = {
                    'id': line[:10],
                    'offset': meta[0][7:],
                    'BW': meta[1][3:],
                    'MCS': meta[2][4:],
                    'size': meta[3][5:],
                    'bits': meta[4][5:-1]
                }
                self.frame_data.append(current_frame)
        print(*self.frame_data[:100], sep='\n')


finder = Finder()
finder.parse_data('../data/frames_phy.log')
