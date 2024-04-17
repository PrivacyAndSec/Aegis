import numpy as np
from Ring_polynomial import Rq
import well_formedness_proof as WFP
import RLWE
import L_Infry_norm as LIN
import L_2_norm as L2N

import socket

class User:
    def __init__(self, id, dimension, rlwe, t, n, q, d, B_I,B_2, NIZK):
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