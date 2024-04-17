from sympy.polys.domains import GF
from sympy.polys.rings import ring
import numpy as np
# 定义模数q和多项式的变量x
q = 69876453465  # 模数
t = 123456789
n = 2**20  # 多项式的最大次数（示例用途）

# 创建一个多项式环 Fq[x]
R, x = ring('x', GF(q))
Rt, xt = ring('x', GF(t))

def convert_coeffs_to_new_mod(coeffs, q, t):
    """将系数从Z_q环转换到Z_t环"""
    converted_coeffs = [(coeff % q) % t for coeff in coeffs]
    return converted_coeffs


# 自定义函数，通过系数列表创建多项式
def create_poly_from_coeffs(coeffs, R, x):
    # 从高次到低次遍历系数，并构建多项式
    poly = R.zero
    for i, coeff in enumerate(coeffs[::-1]):
        poly += coeff * x**i
    return poly
# 示例系数列表 [1, 2, 1] 对应于多项式 x^2 + 2x + 1
coeffs = np.zeros(n)
# 使用系数列表创建多项式
p1 = create_poly_from_coeffs(coeffs, R, x)
coeffs = np.ones(n)
# 使用系数列表创建多项式
p2 = create_poly_from_coeffs(coeffs, R, x)


A = p1
S = p1
M = p1
e = p2
print(M)
c = (A * S + M )% (x**n + 1)

de_c = (c - A * S) % (x**n + 1)

coeffs_equal_p1_p2 = M.coeffs() == de_c.coeffs()
print(f"p1 和 p2 的系数是否相等: {coeffs_equal_p1_p2}")

M_coeffs_in_Zt = convert_coeffs_to_new_mod(M.coeffs(), q, t)
Mt = create_poly_from_coeffs(M_coeffs_in_Zt, Rt, xt)
print(f"转换后的多项式Mt: {Mt}")
