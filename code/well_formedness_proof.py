import numpy as np
#from sympy import nextprime
#from secrets import randbelow, randbits
from Ring_polynomial import Rq
import hashlib


def hash_to_int(arr, q):
    # 将NumPy数组转换为字节字符串
    arr_bytes = arr.tobytes()

    # 使用hashlib创建哈希对象，这里以SHA-256为例
    hash_obj = hashlib.sha256(arr_bytes)

    # 生成哈希摘要，并转换为大整数
    hash_digest = hash_obj.digest()  # 获取字节摘要
    hash_int = int.from_bytes(hash_digest, byteorder='big')  # 将字节转换为整数

    # 对该整数进行取模 q 的运算
    hash_mod_q = hash_int % q

    return hash_mod_q

class KeyWellformednessProof:
    def __init__(self, rlwe, A, A_other, NIZK):
        # Prover 生成随机多项式和噪声
        self.s_c = Rq(np.random.randint(0, rlwe.q, rlwe.n, dtype='int64'), rlwe.q)
        self.x_c = Rq(np.random.randint(0, rlwe.q, rlwe.n, dtype='int64'), rlwe.q)
        self.eta = Rq(np.round(rlwe.std * np.random.randn(rlwe.n)), rlwe.q)
        self.eta_c = Rq(np.round(rlwe.std * np.random.randn(rlwe.n)), rlwe.q)
        zero = Rq(np.zeros(rlwe.n), rlwe.t)
        # Prover 计算 t1 和 t2
        self.t1 = rlwe.encrypt(self.x_c, A, self.s_c, e=self.eta)
        self.t2 = rlwe.encrypt(zero, A_other, self.s_c, e=self.eta_c)
        # Prover 发送 t1 和 t2 给 Verifier
        if NIZK is True:
            self.challenge = hash_to_int(np.sum(self.t1.poly) + np.sum(self.t2.poly), rlwe.q)
        else:
            self.challenge = None


    def sigma_protocol_response(self, x, s, e, e_other, challenge, t):
        # Prover 根据挑战 c 计算并发送回应
        if self.challenge is None:
            self.challenge = challenge
        x = Rq(x.poly, self.x_c.q)  # 原密文是在R_t的环上，将其转移到R_q的多项式环。
        S_x = self.x_c + self.challenge * x # 这里使用简单的标量乘法模拟 RLWE 中的运算
        S_s = self.s_c + self.challenge * s
        S_e = t * (self.eta_c + self.eta) +t * self.challenge * (e + e_other)
        return S_s, S_x, S_e

# 验证

class KeyWellformednessVerify:
    def __init__(self, t1, t2, q, n, t, s, rlwe, NIZK):
        self.t1 = t1
        self.t2 = t2
        if NIZK is True:
            self.c = hash_to_int(np.sum(self.t1.poly) + np.sum(self.t2.poly), rlwe.q)
        else:
            self.c = np.random.randint(1, q, dtype='int64')
        self.t = t
        self.n = n
        self.s = s
        self.rlwe = rlwe

    def verify(self, A, A_other, S_s, S_x, S_e, c1, c2):
        lhs = (A + A_other) * S_s + S_x + S_e
        rhs = self.t1 + self.t2 + self.c*(c1 + c2)
        zero = Rq(np.zeros(self.n), self.t)
        verify = self.rlwe.decrypt(rhs - lhs, self.s, zero)
        if np.all(verify.poly== 0):
            return True
        else:
            return False
