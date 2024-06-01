import numpy as np
import Ring_polynomial
class RLWE:
    def __init__(self, n, q, t, std):
        assert np.log2(n) == int(np.log2(n))
        self.n = n #多项式维度
        self.q = q #密文模数
        self.t = t #明文模数
        self.std = std # 方差

    def generate_public_keys(self, ts, type=None):
        A = discrete_uniform(self.n, self.q,ts, type) #用随机数当作环多项式的系数，生成公钥A
        return A

    def generate_secret_keys(self, ts):
        s = discrete_uniform(self.n, self.q,ts+783) #用随机数当作环多项式的系数，生成公钥A
        return s

    def encrypt(self, m, A, s, e=None, q=None):
        if e is None:
            e = discrete_gaussian(self.n, self.q, 1+57333, type=None)
        if q is None:
            q = self.q
        m = Ring_polynomial.Rq(m.poly, q) #原密文是在R_t的环上，将其转移到R_q的多项式环。
        x = A * s + m + self.t * e
        return x

    def decrypt(self, c, A, s, t=None):
        if t is None:
            t = self.t
        m = Ring_polynomial.Rq((c - A * s).poly, t)
        return m

def discrete_gaussian(n, q, ts, type=None, mean=0., std=1.):
    if type is "encrypt s":
        ts = ts + 107632
    elif type is "encrypt e":
        ts = ts + 10763123
    np.random.seed(ts)
    coeffs = np.round(std * np.random.randn(n))
    return Ring_polynomial.Rq(coeffs, q)

def discrete_uniform(n, q, ts, type=None, min=0., max=None):
    if type is None:
        ts = ts + 107632
    if max is None:
        max = q
    np.random.seed(ts)
    coeffs = np.random.randint(min, max, size=n, dtype='int64')
    return Ring_polynomial.Rq(coeffs, q)

def crange(coeffs, q):
    coeffs = np.where((coeffs >= 0) & (coeffs <= q//2),
                      coeffs,
                      coeffs - q)

    return coeffs