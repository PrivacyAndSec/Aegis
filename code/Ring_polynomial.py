import numpy as np

def crange(coeffs, q):
    coeffs = np.where((coeffs >= 0) & (coeffs <= q//2),coeffs,coeffs - q)

    return coeffs
def poly_divmod(p, divisor, q):
    """多项式除法，返回商和余数，这里以 x^n + 1 为除数进行模运算"""
    # 确保除数是 x^n + 1 的形式
    n = len(divisor) - 2  # 除数的形式应为 [1, 0, ..., 0, 1]
    assert divisor == [1] + [0] * n + [1], "除数必须是 x^n + 1 的形式"

    # 模拟多项式除法算法，实际上这里我们只需要余数
    remainder = p[:]
    for i in range(len(p) - len(divisor) + 1):
        coeff = remainder[i]
        if coeff != 0:
            for j in range(1, len(divisor)):
                if divisor[j] != 0:
                    if i + j < len(remainder):
                        remainder[i + j] = (remainder[i + j] - coeff * divisor[j]) % q
    return remainder[:len(divisor) - 1]


class Rq(object):

    #Ring-Polynomial: Fq[x] / (x^n + 1)
        #range of the reminder is set to (−q/2, q/2]

    def __init__(self, coeffs, q):
        n = len(coeffs)  # degree of a polynomial

        self.f = [1] + [0] * (n - 1) + [1]

        self.q = q
        coeffs = np.array(coeffs, dtype=np.int64) % q
        coeffs = crange(coeffs, q)
        self.poly = coeffs

    def __repr__(self):
        template = 'Rq: {} (mod {}), reminder range: ({}, {}]'
        return template.format(self.poly.__repr__(), self.q,
                               -self.q//2, self.q//2)

    def __len__(self):
        return len(self.poly)  # degree of a polynomial

    def __add__(self, other):
        result = [0] * max(len(self.poly), len(other.poly))
        for i in range(len(result)):
            coef1 = self.poly[i] if i < len(self.poly) else 0
            coef2 = other.poly[i] if i < len(other.poly) else 0
            result[i] = (coef1 + coef2) % self.q
        return Rq(result, self.q)

    def __sub__(self, other):
        result = [0] * max(len(self.poly), len(other.poly))
        for i in range(len(result)):
            coef1 = self.poly[i] if i < len(self.poly) else 0
            coef2 = other.poly[i] if i < len(other.poly) else 0
            result[i] = (coef1 - coef2) % self.q
        return Rq(result, self.q)

    def __mul__(self, other):
        if len(self.poly) < len(other.poly):
            self.poly, other.poly = other.poly, self.poly

        result = np.polymul(self.poly, other.poly)

        result = poly_divmod(result, self.f, self.q)
        return Rq(result, self.q)

    def __rmul__(self, integer):
        coeffs = (self.poly * integer)
        return Rq(coeffs, self.q)


