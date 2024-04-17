from sympy.polys.domains import GF
from sympy.polys.rings import ring
import numpy as np


'''
class Rq2(object):

    #Ring-Polynomial: Fq[x] / (x^n + 1)
        #range of the reminder is set to (−q/2, q/2]

    def __init__(self, coeffs, q):
        
        # Args
            #coeffs: coefficients array of a polynomial
            #q: modulus
        n = len(coeffs)  # degree of a polynomial
        R, x = ring('x', GF(q))
        self.f = x**n + 1

        self.q = q
        coeffs = np.array(coeffs, dtype=np.int64) % q
        #coeffs = crange(coeffs, q)
        self.poly = self.create_poly_from_coeffs(coeffs, R, x)

    def create_poly_from_coeffs(self, coeffs, R, x):
        # 从高次到低次遍历系数，并构建多项式
        poly = R.zero
        for i, coeff in enumerate(coeffs[::-1]):
            poly += coeff * x ** i
        return poly

    def __add__(self, other):
        result = self.poly + other.poly

        return Rq2(result, self.q)
    def __mul__(self, other):
        result = self.poly * other.poly
        result = result % self.f
        return ()
n = 10
coef = np.ones(n)
q= 123123
A = Rq2(coef, q)
S = Rq2(coef, q)
M = Rq2(coef, q)


c = (A * S + M )

de_c = (c - A * S)

coeffs_equal_p1_p2 = M.coeffs() == de_c.coeffs()
print(f"p1 和 p2 的系数是否相等: {coeffs_equal_p1_p2}")

'''
class Rq(object):

    #Ring-Polynomial: Fq[x] / (x^n + 1)
        #range of the reminder is set to (−q/2, q/2]

    def __init__(self, coeffs, q):
        n = len(coeffs)  # degree of a polynomial

        self.f = [1] + [0] * (n - 1) + [1]

        self.q = q
        coeffs = np.array(coeffs, dtype=np.int64) % q
        #coeffs = crange(coeffs, q)
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
        mid = len(self.poly) // 2
        a0, a1 = self.poly[:mid], self.poly[mid:]
        b0, b1 = other.poly[:mid], other.poly[mid:]

        z0 = (a0 + a1) * (b0 + b1)
        z1 = (a0 - a1) * (b0 - b1)
        z2 = (a0 + a1) * (b0 - b1)
        z3 = (a0 - a1) * (b0 + b1)

        result = [0] * (len(self.poly) + len(other.poly) - 1)
        result[:mid] = z0 - z1 - z2 + z3
        result[mid:mid * 2] = z1 + z2
        result[mid * 2:] = z0 + z1

        result = poly_divmod(result, self.f, q)
        return Rq(result, self.q)

    def __rmul__(self, integer):
        result = (self.poly * integer)
        return Rq(result, self.q)


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


# 示例使用
q = 69876453465  # 模数
n = 3  # 多项式的最大次数（示例用途）
coeffs = [1,2,3]
# 使用系数列表创建多项式
p1 = PolyRing(coeffs, q)
coeffs = np.ones(n)
# 使用系数列表创建多项式
p2 = PolyRing(coeffs, q)

A = p1
S = p1
M = p1
e = p2

c = A * S + M

de_c = (c - A * S)
print(M)

print(de_c)

