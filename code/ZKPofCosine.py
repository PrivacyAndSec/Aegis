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


class XXWellformednessProof:
    def __init__(self, rlwe, A, beta, c1, x1, s1, e1, NIZK):
        # Prover 生成随机多项式和噪声
        self.beta = beta

        self.s_list = [s1]
        self.e_list = [e1]
        for i in range(1,3):
            self.s_list.append(Rq(np.random.randint(0, rlwe.q, rlwe.n, dtype='int64'), rlwe.q))
            self.e_list.append(Rq(np.round(rlwe.std * np.random.randn(rlwe.n)), rlwe.q))

        self.mu_list = []
        self.rho_list = []
        self.r_list = []
        for i in range(0,3):
            self.mu_list.append(Rq(np.random.randint(0, rlwe.q, rlwe.n, dtype='int64'), rlwe.q))
            self.rho_list.append(Rq(np.random.randint(0, rlwe.q, rlwe.n, dtype='int64'), rlwe.q))
            self.r_list.append(Rq(np.round(rlwe.std * np.random.randn(rlwe.n)), rlwe.q))

        self.rho_w = Rq(np.random.randint(0, rlwe.q, rlwe.n, dtype='int64'), rlwe.q)
        self.r_w = Rq(np.round(rlwe.std * np.random.randn(rlwe.n)), rlwe.q)

        self.x_list = [
            x1,
            beta * Rq(np.array([np.sum(x1.poly) % rlwe.q] + [0] * (rlwe.n - 1)), rlwe.q),
            Rq(np.array([np.sum(self.mu_list[0].poly) % rlwe.q] + [0] * (rlwe.n - 1)), rlwe.q)
        ]

        # Prover 计算 tj 和 cj,t_w
        self.t_list = []
        for i in range(0, 3):
            self.t_list.append(rlwe.encrypt(self.mu_list[i], A, self.rho_list[i], e=self.r_list[i]))

        self.c_list = [c1]
        for i in range(1, 3):
            self.c_list.append(rlwe.encrypt(self.x_list[i], A, self.s_list[i], e=self.e_list[i]))

        zero = Rq(np.zeros(rlwe.n), rlwe.q)
        self.t_w = rlwe.encrypt(zero, A, self.rho_w, e=self.r_w)

        if NIZK is True:
            self.challenge = hash_to_int(np.sum(self.c_list[1].poly) + np.sum(self.c_list[2].poly), rlwe.q)
        else:
            self.challenge = None


    def wfp_xx_response(self,  challenge):
        # Prover 根据挑战 c 计算并发送回应
        if self.challenge is None:
            self.challenge = challenge

        S_x_list = []
        S_s_list = []
        S_e_list = []
        for i in range(0,3):
            S_x_list.append(self.mu_list[i] + self.challenge * Rq(self.x_list[i].poly, self.mu_list[i].q))
            S_s_list.append(self.rho_list[i] + self.challenge * self.s_list[i])
            S_e_list.append(self.r_list[i] + self.challenge * self.e_list[i])

        s_w = -self.challenge * self.s_list[1] - self.beta * self.s_list[2]
        e_w = -self.challenge * self.e_list[1] - self.beta * self.e_list[2]

        S_s_w = self.rho_w + self.challenge * s_w
        S_e_w = self.r_w + self.challenge * e_w

        return S_s_list, S_x_list, S_e_list, S_s_w, S_e_w


class XXWellformednessVerify:
    def __init__(self, c_list, t_list, t_w, q, n, t,  s, rlwe, beta, NIZK):
        self.c_list = c_list
        self.t_list = t_list
        self.t_w = t_w
        if NIZK is True:
            self.c = hash_to_int(np.sum(self.c_list[1].poly) + np.sum(self.c_list[2].poly), rlwe.q)
        else:
            self.c = np.random.randint(1, round(q/t -1.5, ), dtype='int64')
        self.q = q
        self.t = t
        self.s = s
        self.n = n
        self.rlwe = rlwe
        self.beta = beta

    def verify(self, A, S_s_list, S_x_list, S_e_list, S_s_w, S_e_w):
        error = ""
        for i in range(0,3):
            lhs = A * S_s_list[i] + S_x_list[i] + self.rlwe.t * S_e_list[i]
            rhs = self.t_list[i] + self.c * self.c_list[i]
            zero = Rq(np.zeros(self.n), self.t)
            verify = self.rlwe.decrypt(rhs - lhs, self.s, zero)

            if verify.poly.any() != 0:
                error = error + "XX verify 1 is not correct(for j = {})".format(i+1)

        temp = np.zeros(self.rlwe.n)
        temp[0] = np.sum(S_x_list[0].poly)
        S_X_1 = self.beta * Rq(temp, self.rlwe.q)
        c_w = S_X_1 - self.c * self.c_list[1] - self.beta * self.c_list[2]

        lhs = A * S_s_w + self.t * S_e_w
        rhs = self.t_w + self.c * c_w

        zero = Rq(np.zeros(self.n), self.t)
        verify = self.rlwe.decrypt(rhs - lhs, self.s, zero)

        if verify.poly.any() != 0:
            error = error + "XX verify 2 is not correct"
            return error
        else:
            return error



class XYWellformednessProof:
    def __init__(self, rlwe, A, y, c1, x1, s1, e1, NIZK):
        # Prover 生成随机多项式和噪声
        self.y = y
        self.q = rlwe.q
        self.t = rlwe.t
        self.A = A
        self.rlwe = rlwe

        self.s_list = [s1]
        self.e_list = [e1]
        for i in range(1,5):
            self.s_list.append(Rq(np.random.randint(0, rlwe.q, rlwe.n, dtype='int64'), rlwe.q))
            self.e_list.append(Rq(np.round(rlwe.std * np.random.randn(rlwe.n)), rlwe.q))

        self.mu_list = []
        self.rho_list = []
        self.r_list = []
        for i in range(0,5):
            self.mu_list.append(Rq(np.random.randint(0, rlwe.q, rlwe.n, dtype='int64'), rlwe.q))
            self.rho_list.append(Rq(np.random.randint(0, rlwe.q, rlwe.n, dtype='int64'), rlwe.q))
            self.r_list.append(Rq(np.round(rlwe.std * np.random.randn(rlwe.n)), rlwe.q))

        self.rho_w_list = []
        self.r_w_list = []
        for i in range(0,2):
            self.rho_w_list.append(Rq(np.random.randint(0, rlwe.q, rlwe.n, dtype='int64'), rlwe.q))
            self.r_w_list.append(Rq(np.round(rlwe.std * np.random.randn(rlwe.n)), rlwe.q))

        # Creating x2 directly from the product of polynomials x1 and y
        x2 = Rq(x1.poly * y.poly, rlwe.q)
        x2_sum = np.sum(x2.poly) % self.q
        mu2_sum = np.sum(self.mu_list[1].poly) % self.q

        # Generating x3, x4, and x5 using direct assignment to the zeroth element of a new array
        x3 = Rq(np.array([x2_sum * x2_sum % self.q] + [0] * (rlwe.n - 1)), rlwe.q)
        x4 = Rq(np.array([mu2_sum * mu2_sum % self.q] + [0] * (rlwe.n - 1)), rlwe.q)
        x5 = Rq(np.array([x2_sum * mu2_sum % self.q] + [0] * (rlwe.n - 1)), rlwe.q)

        # Appending all x values to the x_list
        self.x_list = [x1, x2, x3, x4, x5]

        # Prover 计算 tj 和 cj,t_w
        self.t_list = []
        for i in range(0, 5):
            self.t_list.append(rlwe.encrypt(self.mu_list[i], A, self.rho_list[i], e=self.r_list[i]))

        self.c_list = [c1]
        for i in range(1, 5):
            self.c_list.append(rlwe.encrypt(self.x_list[i], A, self.s_list[i], e=self.e_list[i]))

        self.t_w_list = []
        zero = Rq(np.zeros(rlwe.n), rlwe.t)
        for i in range(0, 2):
            self.t_w_list.append(rlwe.encrypt(zero, A, self.rho_w_list[i], e=self.r_w_list[i]))

        if NIZK is True:
            self.challenge = hash_to_int(np.sum(self.c_list[1].poly) + np.sum(self.c_list[2].poly), rlwe.q)
        else:
            self.challenge = None

    def wfp_xy_response(self, challenge):
        # Prover 根据挑战 c 计算并发送回应
        if self.challenge is None:
            self.challenge = challenge

        S_x_list = []
        S_s_list = []
        S_e_list = []
        for i in range(0, 5):
            S_x_list.append(self.mu_list[i] + self.challenge * Rq(self.x_list[i].poly, self.q))
            S_s_list.append(self.rho_list[i] + self.challenge * self.s_list[i])
            S_e_list.append(self.r_list[i] + self.challenge * self.e_list[i])

        s_w1 = -self.challenge * self.s_list[1] - Rq(self.rho_list[0].poly * self.y.poly, self.q)
        e_w1 = -self.challenge * self.e_list[1] - Rq(self.r_list[0].poly * self.y.poly, self.q)

        c = (self.challenge * self.challenge) % self.q
        s_w2 = -c * self.s_list[2] - 2 * self.challenge * self.s_list[4] - self.s_list[3]
        e_w2 = -c * self.e_list[2] - 2 * self.challenge * self.e_list[4] - self.e_list[3]

        S_s_w_list = [self.rho_w_list[0] + self.challenge * s_w1, self.rho_w_list[1] + self.challenge * s_w2]
        S_e_w_list = [self.r_w_list[0] + self.challenge * e_w1, self.r_w_list[1] + self.challenge * e_w2]

        return S_s_list, S_x_list, S_e_list, S_s_w_list, S_e_w_list



class XYWellformednessVerify:
    def __init__(self,y, c_list, t_list, t_w_list, q, n, t,  s, rlwe,  NIZK):
        self.y = y
        self.c_list = c_list
        self.t_list = t_list
        self.t_w_list = t_w_list
        if NIZK is True:
            self.c = hash_to_int(np.sum(self.c_list[1].poly) + np.sum(self.c_list[2].poly), rlwe.q)
        else:
            self.c = np.random.randint(1, round(q/t -1.5, ), dtype='int64')
        self.q = q
        self.t = t
        self.s = s
        self.n = n
        self.rlwe = rlwe

    def verify(self, A, S_s_list, S_x_list, S_e_list, S_s_w_list, S_e_w_list):
        error = ""
        for i in range(0,5):
            lhs = A * S_s_list[i] + S_x_list[i] + self.rlwe.t * S_e_list[i]
            rhs = self.t_list[i] + self.c * self.c_list[i]
            zero = Rq(np.zeros(self.n), self.t)
            verify = self.rlwe.decrypt(rhs - lhs, self.s, zero)
            if verify.poly.any() != 0:
                error = error + "XY verify 3 is not correct(for j = {})".format(i+1)

        # Directly calculate polynomial products and construct Rq objects
        c_w_1 = Rq(S_x_list[0].poly * self.y.poly, self.rlwe.q) - self.c * self.c_list[1] - Rq(self.t_list[0].poly * self.y.poly, self.rlwe.q)
        # Compute S_X_2 using direct assignment to avoid temporary zero array
        S_x_2 = np.sum(S_x_list[1].poly) % self.q
        c2 = (self.c * self.c) % self.q
        c_w_2 = Rq(np.array([S_x_2 * S_x_2 % self.q] + [0] * (self.rlwe.n - 1)), self.rlwe.q) - c2 * self.c_list[2] - 2 * self.c * self.c_list[4] - self.c_list[3]
        c_w_list = [c_w_1, c_w_2]

        for i in range(0, 2):
            lhs = A * S_s_w_list[i] + self.t * S_e_w_list[i]
            rhs = self.t_w_list[i] + self.c * c_w_list[i]

            zero = Rq(np.zeros(self.n), self.t)
            verify = self.rlwe.decrypt(rhs - lhs, self.s, zero)
            if verify.poly.any() != 0:
                error = "XY verify 4 is not correct(for k = {})".format(i+1)
        if error == "":
            error = "correct"

        return error

class RangeProof:
    def __init__(self, v, rlwe, A, c, x_L, x_R, s, e, NIZK):
        # Prover 生成随机多项式和噪声
        self.c = c
        self.x_L = x_L
        self.x_R = x_R
        self.s = s
        self.e = e
        self.rlwe = rlwe
        self.A = A
        self.v = v

        self.S_L = Rq(np.random.randint(0, rlwe.q, rlwe.n, dtype='int64'), rlwe.q)
        self.S_R = Rq(np.random.randint(0, rlwe.q, rlwe.n, dtype='int64'), rlwe.q)
        self.tau_1 = Rq(np.random.randint(0, rlwe.q, rlwe.n, dtype='int64'), rlwe.q)
        self.tau_2 = Rq(np.random.randint(0, rlwe.q, rlwe.n, dtype='int64'), rlwe.q)

        self.e_x = Rq(np.round(rlwe.std * np.random.randn(rlwe.n)), rlwe.q)
        self.e_s = Rq(np.round(rlwe.std * np.random.randn(rlwe.n)), rlwe.q)
        self.epslion_1 = Rq(np.round(rlwe.std * np.random.randn(rlwe.n)), rlwe.q)
        self.epslion_2 = Rq(np.round(rlwe.std * np.random.randn(rlwe.n)), rlwe.q)

        self.X = rlwe.encrypt(self.x_L, A, self.x_R, e=self.e_x)
        self.S = rlwe.encrypt(self.S_L, A, self.S_R, e=self.e_s)

        if NIZK is True:
            self.b = hash_to_int(np.sum(self.X.poly) - np.sum(self.S.poly), rlwe.q)
            self.z = hash_to_int(np.sum(self.X.poly) + np.sum(self.S.poly), rlwe.q)
            self.x = 1
        else:
            self.b = None
            self.z = None
            self.x = None


    def response_t(self,  b, z):
        # Prover 根据挑战 c 计算并发送回应
        if self.b is None:
            self.b = b
            self.z = z
        rlwe = self.rlwe
        n = rlwe.n
        q = rlwe.q
        ones_n = Rq(np.ones(n), q)
        # Rq对象初始化
        self.b_rq = Rq(self.b ** np.arange(n), q)
        self.z_rq = Rq(self.z ** np.arange(n), q)
        self.two_rq = Rq(2 ** np.arange(n), q)

        z_sq_mod = self.z * self.z % q
        self.L = self.x_L - self.z * ones_n
        temp = self.x_R + self.z * ones_n
        self.R = Rq(self.b_rq.poly * temp.poly, q) + (z_sq_mod * self.two_rq)

        # 计算sigma

        t_1 = np.sum(self.S_L.poly * self.R.poly % q) % q + np.sum(self.L.poly * Rq(self.S_R.poly * self.b_rq.poly, q).poly % q)
        t_2 = np.sum((self.S_L * self.S_R).poly * self.b_rq.poly % q)

        coeff_t1 = np.zeros(self.rlwe.n)
        coeff_t1[0] = t_1 % q
        coeff_t2 = np.zeros(self.rlwe.n)
        coeff_t2[0] = t_2 % q

        self.t_1 = Rq(coeff_t1, self.rlwe.q)
        self.t_2 = Rq(coeff_t2, self.rlwe.q)

        T_list = []
        T_list.append(self.rlwe.encrypt(self.t_1, self.A, self.tau_1, e=self.epslion_1, q=2))
        T_list.append(self.rlwe.encrypt(self.t_2, self.A, self.tau_2, e=self.epslion_2, q=2))

        if self.x is 1:
            self.x = hash_to_int(np.sum(T_list[0].poly) + np.sum(T_list[1].poly), self.rlwe.q)
        return T_list

    def response_proof(self, x):
        if self.x is None:
            self.x = x
        self.L_x = self.L + self.x * self.S_L
        self.R_x = self.R + self.x * Rq(self.S_R.poly * self.b_rq.poly, self.rlwe.q)
        self.E_x = self.rlwe.t * self.e_x + (self.x * self.rlwe.t % self.rlwe.q) * self.e_s

        self.tau_x = (self.z * self.z % self.rlwe.q) * self.s + self.x * self.tau_1 + (self.x * self.x % self.rlwe.q) * self.tau_2
        self.T_e = (self.z * self.z % self.rlwe.q) * self.e + self.x * self.epslion_1 + (self.x * self.x % self.rlwe.q) * self.epslion_2

        self.t_hat = np.zeros(self.rlwe.n)
        self.t_hat[0] = np.sum(self.L_x.poly * self.R_x.poly % self.rlwe.q)
        self.t_hat = Rq(self.t_hat, self.rlwe.q)

        return self.L_x, self.R_x, self.E_x, self.t_hat, self.tau_x, self.T_e



class RangeVerify:
    def __init__(self, X, S, c, q, n, t,  s, rlwe, NIZK):
        self.X = X
        self.S = S
        self.c = c
        self.NIZK = NIZK
        if NIZK is True:
            self.b = hash_to_int(np.sum(self.X.poly) - np.sum(self.S.poly), rlwe.q)
            self.z = hash_to_int(np.sum(self.X.poly) + np.sum(self.S.poly), rlwe.q)
            self.x = 1
        else:
            self.b = np.random.randint(1, round(q/t -1.5, ), dtype='int64')
            self.z = np.random.randint(1, round(q / t - 1.5, ), dtype='int64')
            self.x = np.random.randint(1, round(q / t - 1.5, ), dtype='int64')
        self.q = q
        self.t = t
        self.s = s
        self.n = n
        self.rlwe = rlwe
        self.T_list = None

        self.b_rq = Rq(self.b ** np.arange(self.rlwe.n), self.rlwe.q)
        self.z_rq = Rq(self.z ** np.arange(self.rlwe.n), self.rlwe.q)
        self.two_rq = Rq(2 ** np.arange(self.rlwe.n), self.rlwe.q)

    def challenge2(self, T_list):
        self.T_list = T_list
        if self.NIZK is True:
            self.x = hash_to_int(np.sum(T_list[0].poly) + np.sum(T_list[1].poly), self.rlwe.q)


    def verify(self, A, L_x, R_x, E_x, t_hat, tau_x, T_e):
        ones_n = Rq(np.ones(self.n), self.q)
        zero = Rq(np.zeros(self.n), self.t)
        z_sq_mod = self.z * self.z % self.q

        lhs = t_hat
        rhs = np.zeros(self.rlwe.n)
        rhs[0] = np.sum(L_x.poly * R_x.poly % self.rlwe.q)
        rhs = Rq(rhs, self.rlwe.q)


        verify = self.rlwe.decrypt(rhs - lhs, self.s, zero)
        error = ""
        if verify.poly.any() != 0:
            error = error + "Range Proof verify 3 is not correct\n"



        sigma = np.zeros(self.n)
        temp1 = (self.z - z_sq_mod) % self.q
        temp2 = np.sum(ones_n.poly * self.b_rq.poly) % self.q
        temp3 = (temp1 * temp2) % self.q

        temp4 = (z_sq_mod * self.z) % self.q
        temp5 = np.sum(ones_n.poly * self.two_rq.poly) % self.q
        temp6 = (temp4 * temp5) % self.q

        sigma[0] = (temp3 - temp6) % self.rlwe.q
        sigma = Rq(sigma, self.rlwe.q)
        lhs = A * tau_x + t_hat + self.t * T_e
        coef1 = self.z * self.z % self.rlwe.q
        coef2 = (self.x * self.x) % self.rlwe.q
        rhs = coef1 * self.c + self.x * self.T_list[0] + coef2 * self.T_list[1] + sigma

        verify = self.rlwe.decrypt(rhs - lhs, self.s, zero)
        if verify.poly.any() != 0:
            error = error + "Range Proof verify 1 is not correct\n"



        lhs = Rq(L_x.poly * self.b_rq.poly, self.rlwe.q) + Rq(E_x.poly * self.b_rq.poly, self.rlwe.q) +  A * R_x
        rhs = self.z * ones_n * Rq(A.poly * self.b_rq.poly , self.rlwe.q) + \
              Rq(self.X.poly * self.b_rq.poly, self.rlwe.q) + self.x * Rq(self.S.poly * self.b_rq.poly , self.rlwe.q) - \
              self.z * Rq(self.b_rq.poly * ones_n.poly, self.rlwe.q) + (self.z * self.z % self.q) * A * Rq(self.two_rq.poly * ones_n.poly, self.rlwe.q)

        verify = self.rlwe.decrypt(rhs - lhs, self.s, zero)
        if verify.poly.any() != 0:
            error = error + "Range Proof verify 2 is not correct"
            return error
        else:
            return error



