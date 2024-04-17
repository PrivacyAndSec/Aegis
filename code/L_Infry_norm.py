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


class LInftyNormProof:
    def __init__(self, rlwe, A, B_I, NIZK):
        # Prover 生成随机多项式和噪声
        self.rlwe = rlwe
        self.s_c = Rq(np.random.randint(0, rlwe.q, rlwe.n, dtype='int64'), rlwe.q)
        self.x_c = Rq(np.random.randint(-B_I, B_I, rlwe.n, dtype='int64'), rlwe.q)
        self.e_c = Rq(np.round(rlwe.std * np.random.randn(rlwe.n)), rlwe.q)
        self.L = rlwe.encrypt(self.x_c, A, self.s_c, e=self.e_c)
        if NIZK is True:
            self.challenge = hash_to_int(np.sum(self.L.poly), round(rlwe.q/rlwe.t -1.5))
        else:
            self.challenge = None

    def protocol_response(self, x, s, e, challenge):
        # Prover 根据挑战 c 计算并发送回应
        if self.challenge is None:
            self.challenge = challenge
        x = Rq(x.poly, self.x_c.q)  # 原密文是在R_t的环上，将其转移到R_q的多项式环。
        S_x = self.x_c + self.challenge * x # 这里使用简单的标量乘法模拟 RLWE 中的运算
        S_s = self.s_c + self.challenge * s
        S_e = self.rlwe.t * self.e_c +self.rlwe.t * self.challenge * e
        return S_s, S_x, S_e

# 验证

class LInftyNormVerify:
    def __init__(self, L, q, n, t, s, rlwe, B_I, NIZK):
        self.L = L
        if NIZK is True:
            self.c = hash_to_int(np.sum(self.L.poly), round(q/t -1.5))
        else:
            self.c = np.random.randint(1, round(q/t -1.5, ), dtype='int64')
        self.t = t
        self.n = n
        self.s = s
        self.rlwe = rlwe
        self.B_I = B_I

    def verify(self, A, S_s, S_x, S_e, c1):
        lhs = A * S_s + S_x + S_e
        rhs = self.L + self.c*c1
        zero = Rq(np.zeros(self.n), self.t)
        verify = self.rlwe.decrypt(rhs - lhs, self.s, zero)

        error = "correct"
        if verify.poly.any() != 0:
            error = "commitments are not correct"
            return error
        else:
            L_I = np.max(np.abs(S_x.poly))
            Bound = self.B_I * (self.c + 1)
            if L_I > Bound:
                error = "message's value beyond the infinite norm bound"
                return error
            else:
                return error
