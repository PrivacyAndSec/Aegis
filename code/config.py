import Main
class Config():
    def __init__(self, d=None):
        if d is not None:
            self.n = d  # power of 2
            self.d = d
        else:
            self.n = 2**13
            self.d = 2**13
        self.std = 3  # standard deviation of Gaussian distribution
        self.ts = 1  # timestamp
        self.d = self.n  # message dimension
        self.N = 1  # User number
        self.NIZK = False
        self.K = 1
        self.q = 671082891  # prime number, q = 1 (mod 2n)
        self.t = 37  # prime number, t < q
        self.B_I = 3
        self.B_2 = self.d+10
        # A high-speed LAN environment with low latency
        # latency_ms=5
        # bandwidth_mbps=2000
        # A typical home internet connection
        self.network = "LAN"
        self.latency_s = 5
        self.bandwidth_mbps = 2000
        self.time_result_path = "result/Optimization/n_{},d_{},NIZK_{},N_{},network_{}_time_Optimization.txt".format(self.n, self.d, self.NIZK, self.N, self.network)
        self.space_result_path = "result/Optimization/n_{},d_{},NIZK_{},N_{},network_{}_space_Optimization.txt".format(self.n, self.d, self.NIZK, self.N, self.network)

    def set_network(self,net):
        if net == 'home':
            self.latency_s = 50
            self.bandwidth_mbps = 100
            self.network = 'home'
        elif net == 'LAN':
            self.latency_s = 5
            self.bandwidth_mbps = 2000
            self.network = 'LAN'
        elif net == 'mobile':
            self.latency_s = 150
            self.bandwidth_mbps = 50
            self.network = 'mobile'
    def set_d(self, d):
        self.d = d
        while self.n < self.d:
            self.n = self.n * 2
        if self.n > 32768:
            print("It is beyond the normal range of NTT")
    def update_path(self, space=None):
        if space is None:
            self.time_result_path = "result/Optimization/n_{},d_{},NIZK_{},N_{},network_{}_time_Optimization.txt".format(self.n, self.d, self.NIZK, self.N, self.network)
            self.space_result_path = "result/Optimization/n_{},d_{},NIZK_{},N_{},network_{}_space_Optimization".format(self.n, self.d, self.NIZK, self.N, self.network)
        elif space is "network":
            self.time_result_path = "result/Network/n_{},d_{},NIZK_{},N_{},network_{}_time_Optimization.txt".format(self.n, self.d,
                                                                                               self.NIZK, self.N,
                                                                                               self.network)
            self.space_result_path = "result/Network/n_{},d_{},NIZK_{},N_{},network_{}_space_Optimization.txt".format(self.n, self.d,
                                                                                                 self.NIZK, self.N,
                                                                                                 self.network)
        else:
            self.time_result_path = "result/Space/n_{},d_{},NIZK_{},N_{},network_{}_time_Optimization.txt".format(self.n, self.d, self.NIZK, self.N, self.network)
            self.space_result_path = "result/Space/n_{},d_{},NIZK_{},N_{},network_{}_space_Optimization.txt".format(self.n, self.d, self.NIZK, self.N, self.network)
def test_d(d_list):
    for d in d_list:
        config = Config(d)
        config.set_d(d)
        config.update_path()
        Main.main(config)

def test_N(N_min, N_max):
    for N in range(N_min, N_max+1):
        config = Config()
        config.N = N
        config.update_path()
        Main.main(config)

def test_NIZK():
    config = Config()
    config.NIZK = True
    config.update_path()
    Main.main(config)

    config = Config()
    config.NIZK = False
    config.update_path()
    Main.main(config)
def test_Network():
    config = Config()
    config.set_network('home')
    config.update_path("network")
    Main.main(config)

    #config = Config()
    #config.set_network('mobile')
    #config.update_path("network")
    #Main.main(config)
def test_run(d):
    config = Config(d)
    Main.main(config)
def test_space(d_list):
    for d in d_list:
        config = Config(d)
        config.set_d(d)
        config.update_path(1)
        Main.main(config)

if __name__ == "__main__":
    #d_list = [2 ** i for i in range(14, 16)]
    #test_d(d_list)
    test_run(d=2)