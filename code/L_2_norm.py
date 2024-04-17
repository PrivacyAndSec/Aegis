import numpy as np
#from sympy import nextprime
#from secrets import randbelow, randbits
from Ring_polynomial import Rq
import hashlib

def generate_scaled_random_integers(n, B_2, B_I):
    # 步骤1: 生成一个随机向量
    random_vector = np.random.uniform(-1, 1, n)

    # 步骤2: 计算比例因子，以使向量的L2范式等于B_2
    L2_norm = np.linalg.norm(random_vector, 2)
    L2_norm = L2_norm * L2_norm
    scale_factor = B_2 / L2_norm

    # 步骤3: 应用比例因子，并确保结果在给定范围内
    scaled_vector = random_vector * scale_factor

    # 步骤4: 将向量元素四舍五入为整数，并确保不超过B_I
    scaled_integers = np.clip(np.round(scaled_vector), -B_I, B_I).astype(int)

    return scaled_integers

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



class L2NormProof:
    def __init__(self, rlwe, A, B_2, B_I, x1, s1, e1, c1, NIZK):
        # Prover 生成随机多项式和噪声
        self.rlwe = rlwe

        self.u_1 = Rq(np.random.randint(0, rlwe.q, rlwe.n, dtype='int64'), rlwe.q)
        self.u_2 = Rq(generate_scaled_random_integers(rlwe.n, B_2, B_I), rlwe.q)
        self.u_mult = Rq(np.random.randint(0, rlwe.q, rlwe.n, dtype='int64'), rlwe.q)
        self.u_plus = Rq(np.random.randint(0, rlwe.q, rlwe.n, dtype='int64'), rlwe.q)

        self.rho_1 = Rq(np.random.randint(0, rlwe.q, rlwe.n, dtype='int64'), rlwe.q)
        self.rho_2 = Rq(np.random.randint(0, rlwe.q, rlwe.n, dtype='int64'), rlwe.q)
        self.rho_mult = Rq(np.random.randint(0, rlwe.q, rlwe.n, dtype='int64'), rlwe.q)
        self.rho_plus = Rq(np.random.randint(0, rlwe.q, rlwe.n, dtype='int64'), rlwe.q)

        self.x_1 = x1
        self.x_2 = Rq(self.x_1.poly * self.x_1.poly, rlwe.q)
        self.x_plus = Rq(2 * self.x_1.poly * self.u_1.poly, rlwe.q)
        self.x_mult = Rq(self.u_1.poly * self.u_1.poly, rlwe.q)

        self.s_1 = s1
        self.s_2 = Rq(np.random.randint(0, rlwe.q, rlwe.n, dtype='int64'), rlwe.q)
        self.s_mult = Rq(np.random.randint(0, rlwe.q, rlwe.n, dtype='int64'), rlwe.q)
        self.s_plus = Rq(np.random.randint(0, rlwe.q, rlwe.n, dtype='int64'), rlwe.q)

        self.e_1 = e1
        self.e_2 = Rq(np.random.randint(0, rlwe.q, rlwe.n, dtype='int64'), rlwe.q)
        self.e_mult = Rq(np.round(rlwe.std * np.random.randn(rlwe.n)), rlwe.q)
        self.e_plus = Rq(np.round(rlwe.std * np.random.randn(rlwe.n)), rlwe.q)

        self.r_1 = Rq(np.round(rlwe.std * np.random.randn(rlwe.n)), rlwe.q)
        self.r_2 = Rq(np.round(rlwe.std * np.random.randn(rlwe.n)), rlwe.q)
        self.r_mult = Rq(np.round(rlwe.std * np.random.randn(rlwe.n)), rlwe.q)
        self.r_plus = Rq(np.round(rlwe.std * np.random.randn(rlwe.n)), rlwe.q)

        self.c_1 = c1
        self.c_2 = rlwe.encrypt(self.x_2, A, self.s_2, self.e_2)
        self.c_mult = rlwe.encrypt(self.x_mult, A, self.s_mult, self.e_mult)
        self.c_plus = rlwe.encrypt(self.x_plus, A, self.s_plus, self.e_plus)

        self.t_1 = rlwe.encrypt(self.u_1, A, self.rho_1, self.r_1)
        self.t_2 = rlwe.encrypt(self.u_2, A, self.rho_2, self.r_2)
        self.t_mult = rlwe.encrypt(self.u_mult, A, self.rho_mult, self.r_mult)
        self.t_plus = rlwe.encrypt(self.u_plus, A, self.rho_plus, self.r_plus)

        self.rho_wave = Rq(np.random.randint(0, rlwe.q, rlwe.n, dtype='int64'), rlwe.q)
        self.r_wave = Rq(np.round(rlwe.std * np.random.randn(rlwe.n)), rlwe.q)
        zero = Rq(np.zeros(rlwe.n), rlwe.t)
        self.t_wave = rlwe.encrypt(zero, A, self.rho_wave, self.r_wave)

        if NIZK is True:
            sums = self.t_1 + self.t_2 + self.t_mult + self.t_plus + self.c_plus + self.c_mult + self.t_wave
            self.challenge = hash_to_int(np.sum(sums.poly), round(rlwe.q/B_2 -1.5))
        else:
            self.challenge = None


    def protocol_response(self, challenge):
        # Prover 根据挑战 c 计算并发送回应
        x_1 = Rq(self.x_1.poly, self.u_1.q)  # 原密文是在R_t的环上，将其转移到R_q的多项式环。

        S_x_1 = self.u_1 + challenge * x_1
        S_x_2 = self.u_2 + challenge * self.x_2
        S_x_mult = self.u_mult + challenge * self.x_mult
        S_x_plus = self.u_plus + challenge * self.x_plus

        S_s_1 = self.rho_1 + challenge * self.s_1
        S_s_2 = self.rho_2 + challenge * self.s_2
        S_s_mult = self.rho_mult + challenge * self.s_mult
        S_s_plus = self.rho_plus + challenge * self.s_plus

        S_e_1 = self.r_1 + challenge * self.e_1
        S_e_2 = self.r_2 + challenge * self.e_2
        S_e_mult = self.r_mult + challenge * self.e_mult
        S_e_plus = self.r_plus + challenge * self.e_plus

        s_wave = -challenge * challenge * self.s_2 - challenge * self.s_plus - self.s_mult
        e_wave = -challenge * challenge * self.e_2 - challenge * self.e_plus - self.e_mult

        S_s_wave = self.rho_wave + challenge * s_wave
        S_e_wave = self.r_wave + challenge * e_wave

        return (S_x_1, S_x_2, S_x_mult, S_x_plus, S_s_1, S_s_2, S_s_mult, S_s_plus, S_e_1,
                S_e_2, S_e_mult, S_e_plus, S_s_wave, S_e_wave)

# 验证

class L2NormVerify:
    def __init__(self, t_1, t_2, t_mult, t_plus, c_plus, c_mult, t_wave, c_2, q, n, t, s, rlwe, B_2, NIZK):
        if NIZK is True:
            sums = t_1 + t_2 + t_mult + t_plus + c_plus + c_mult + t_wave
            self.c = hash_to_int(np.sum(sums.poly), round(q/B_2 -1.5))
        else:
            self.c = np.random.randint(1, 10)
        self.t = t
        self.n = n
        self.s = s
        self.rlwe = rlwe
        self.B_2 = B_2

        self.t_1 = t_1
        self.t_2 = t_2
        self.t_mult = t_mult
        self.t_plus = t_plus
        self.c_plus = c_plus
        self.c_mult = c_mult
        self.t_wave = t_wave
        self.c_2 = c_2

    def verify(self, A, S_x_1, S_x_2, S_x_mult, S_x_plus, S_s_1, S_s_2, S_s_mult, S_s_plus, S_e_1, S_e_2, S_e_mult, S_e_plus, S_s_wave, S_e_wave, c_1):



        c_wave = Rq(S_x_1.poly * S_x_1.poly, self.rlwe.q) -self.c *self.c *self.c_2 - self.c * self.c_plus - self.c_mult

        lhs_wave = A * S_s_wave + self.t * S_e_wave
        rhs_wave = self.t_wave + self.c * c_wave

        lhs_1 = A * S_s_1 + S_x_1 + self.t * S_e_1
        rhs_1 = self.t_1 + self.c * c_1

        lhs_2 = A * S_s_2 + S_x_2 + self.t * S_e_2
        rhs_2 = self.t_2 + self.c * self.c_2

        lhs_mult = A * S_s_mult + S_x_mult + self.t * S_e_mult
        rhs_mult = self.t_mult + self.c * self.c_mult

        lhs_plus = A * S_s_plus + S_x_plus + self.t * S_e_plus
        rhs_plus = self.t_plus + self.c * self.c_plus

        zero = Rq(np.zeros(self.n), self.t)

        verify_1 = self.rlwe.decrypt(rhs_1 - lhs_1, self.s, zero)
        verify_2 = self.rlwe.decrypt(rhs_2 - lhs_2, self.s, zero)
        verify_mult = self.rlwe.decrypt(rhs_mult - lhs_mult, self.s, zero)
        verify_plus = self.rlwe.decrypt(rhs_plus - lhs_plus, self.s, zero)
        verify_wave = self.rlwe.decrypt(rhs_wave - lhs_wave, self.s, zero)

        errors = []
        if np.all(verify_1.poly != 0):
            errors.append('1')
        if np.all(verify_2.poly != 0):
            errors.append('2')
        if np.all(verify_mult.poly != 0):
            errors.append('mult')
        if np.all(verify_plus.poly != 0):
            errors.append('plus')
        if np.all(verify_wave.poly != 0):
            errors.append('wave')

        if len(errors) == 0:
            L2 = np.linalg.norm(S_x_2.poly, 1)
            Bound = self.B_2 * (self.c + 1)
            if L2 > Bound:
                errors.append("L2")
        return errors



