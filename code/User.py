import numpy as np
from Ring_polynomial import Rq
import well_formedness_proof as WFP
import RLWE
import L_Infry_norm as LIN
import L_2_norm as L2N
import ZKPofCosine as cos


import socket

def int_to_padded_binary_array(num, n):
    # 将整数转换为二进制字符串，去除前面的'0b'
    binary_str = bin(num)[2:]

    # 计算需要填充的零的数量
    padding_length = n - len(binary_str)

    # 如果二进制长度小于n，填充零
    if padding_length > 0:
        binary_str = '0' * padding_length + binary_str

    # 将二进制字符串转换为整数数组，每个数字作为数组的一个元素
    # 注意这里我们将字符串反转了，以确保最高位在数组的第一位
    binary_array = np.array([int(bit) for bit in reversed(binary_str)], dtype=int)

    return binary_array

class User:
    def __init__(self, id, dimension, rlwe, t, n, q, d, B_I,B_2, NIZK, y, beta):
        self.id = id
        self.dimension = dimension
        self.rlwe = rlwe
        self.s = None
        self.q = q
        self.A = None
        self.A_other = None
        self.t = t
        self.n = n
        self.x = None
        self.d = d
        self.B_I = B_I
        self.B_2 = B_2
        self.c1 = None
        self.NIZK = NIZK
        self.y = Rq(y, q)
        self.beta = beta


        #well-formedness中的参数
        self.key_WFP = None

        #L-infinity-ynorm-proof中的参数
        self.LIN_Proof = None

        self.L2N_Proof = None


    def generate_data(self):
        # 生成d维数据
        np.random.seed(None)
        #data = np.arange(start=5, step= 10, stop=self.d*10 + 1)+ np.random.randint(low=-3, high=3, size=self.d)
        data = np.ones(self.d)
        if len(data) < self.dimension:
            zero = np.zeros(self.dimension - self.d)
            data = np.concatenate((data, zero))
        self.x = Rq(data, self.t)

    def update_A(self, ts):
        self.A = self.rlwe.generate_public_keys(ts)

    def updata_A_other(self, ts):
        self.A_other = self.rlwe.generate_public_keys(ts, type='other')
    def update_s(self, ts):
        self.s = self.rlwe.generate_secret_keys(ts)
    def encrypted_message(self, ts):
        # 加密并发送数据

        self.e = RLWE.discrete_gaussian(self.n, self.q, ts+5732, type=None)
        encrypted_data = self.rlwe.encrypt(self.x, self.A, self.s, self.e)
        self.c1 = encrypted_data
        return encrypted_data





    def encrypted_s(self, ts):
        zero_m = Rq(np.zeros(self.n),self.t)
        self.e_other = RLWE.discrete_gaussian(self.n, self.q, ts+15732, type=None)
        encrypted_s = self.rlwe.encrypt(zero_m,self.A_other, self.s, self.e_other)
        return encrypted_s

    def sigma_protocol_init(self):
        self.key_WFP = WFP.KeyWellformednessProof(self.rlwe, self.A, self.A_other, self.NIZK)
        return self.key_WFP

    def sigma_protocol_response(self,challenge):
        S_s, S_x, S_e = self.key_WFP.sigma_protocol_response(self.x, self.s, self.e, self.e_other, challenge, self.t)
        return S_s, S_x, S_e

    def L_infry_protocol_init(self):
        self.LIN_Proof = LIN.LInftyNormProof(self.rlwe, self.A, self.B_I, self.NIZK)

        return self.LIN_Proof

    def L_Infty_Norm_response(self, challenge):
        S_s, S_x, S_e = self.LIN_Proof.protocol_response(self.x, self.s, self.e, challenge)
        return S_s, S_x, S_e


    def L_2_protocol_init(self):
        self.L2N_Proof = L2N.L2NormProof(self.rlwe, self.A, self.B_2, self.B_I, self.x, self.s, self.e, self.c1, self.NIZK)
        return self.L2N_Proof

    def L_2_Norm_response(self, challenge):
        S_x_1, S_x_2, S_x_mult, S_x_plus, S_s_1, S_s_2, S_s_mult, S_s_plus, S_e_1, S_e_2, S_e_mult, S_e_plus, S_s_wave, S_e_wave = self.L2N_Proof.protocol_response(challenge)
        return S_x_1, S_x_2, S_x_mult, S_x_plus, S_s_1, S_s_2, S_s_mult, S_s_plus, S_e_1, S_e_2, S_e_mult, S_e_plus, S_s_wave, S_e_wave

    def proof_cosine_init(self):
        c2_p3 = self.L2N_Proof.c_2
        x2_p3 = self.L2N_Proof.x_2
        s2_p3 = self.L2N_Proof.s_2
        e2_p3 = self.L2N_Proof.e_2

        self.XX_Proof = cos.XXWellformednessProof(self.rlwe, self.A, self.beta, c2_p3, x2_p3, s2_p3, e2_p3, self.NIZK)
        self.XY_Proof = cos.XYWellformednessProof(self.rlwe, self.A, self.y, self.c1, self.x, self.s, self.e, self.NIZK)

        c = self.XY_Proof.c_list[2] - self.XX_Proof.c_list[1]
        x = self.XY_Proof.x_list[2] - self.XX_Proof.x_list[1]
        s = self.XY_Proof.s_list[2] - self.XX_Proof.s_list[1]
        e = self.XY_Proof.e_list[2] - self.XX_Proof.e_list[1]
        x_L = Rq(int_to_padded_binary_array(x.poly[0], self.n), self.q)
        x_R = x_L - Rq(np.ones(self.n), self.q)
        self.Range_Proof = cos.RangeProof(x,self.rlwe, self.A, c, x_L, x_R, s, e, self.NIZK)

        return self.XX_Proof, self.XY_Proof, self.Range_Proof

    def cosine_response(self, XX_c, XY_c, RP_b, RP_z):

        S_s_list_xx, S_x_list_xx, S_e_list_xx, S_s_w_xx, S_e_w_xx = self.XX_Proof.wfp_xx_response(XX_c)
        S_s_list_xy, S_x_list_xy, S_e_list_xy, S_s_w_list_xy, S_e_w_list_xy = self.XY_Proof.wfp_xy_response(XY_c)
        T_list_rp = self.Range_Proof.response_t(RP_b, RP_z)

        return S_s_list_xx, S_x_list_xx, S_e_list_xx, S_s_w_xx, S_e_w_xx, \
               S_s_list_xy, S_x_list_xy, S_e_list_xy, S_s_w_list_xy, S_e_w_list_xy, \
               T_list_rp

    def cosine_rp(self, x_rp):
        L_x, R_x, E_x, t_hat, tau_x, T_e = self.Range_Proof.response_proof(x_rp)
        return L_x, R_x, E_x, t_hat, tau_x, T_e