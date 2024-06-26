from Ring_polynomial import Rq
import numpy as np
import well_formedness_proof as WFP
import L_Infry_norm as LIN
import L_2_norm as L2N
import ZKPofCosine as cos


class Aggregator:
    def __init__(self, rlwe, N, d, n, t, q, B_I, B_2, NIZK, beta, y):
        self.c1 = []
        self.c2 = []
        self.rlwe = rlwe
        self.s = None
        self.A = None
        self.A_other = None
        self.N = N
        self.d = d
        self.n = n
        self.t = t
        self.q = q
        self.NIZK = NIZK
        self.beta = beta
        self.y = Rq(y,q)



        self.key_WFP = None

        # L-infinity-ynorm-proof中的参数
        self.LIN_Verify = None
        self.B_I = B_I

        self.L2N_Verify = None
        self.B_2 = B_2


    def receive_c1(self, data):
        # 接收加密数据
        self.c1.append(data)
    def receive_c2(self, data):
        self.c2.append(data)

    def clear_list(self):
        self.c1 = []
        self.c2 = []

    def compute_s_key(self, s):
        if self.s is None:
            self.s = s
        else:
            self.s = self.s+s

    def update_A(self, ts):
        self.A = self.rlwe.generate_public_keys(ts)

    def updata_A_other(self, ts):
        self.A_other = self.rlwe.generate_public_keys(ts, type='other')

    def aggregate_data(self):
        aggregated_message = self.c1[0]
        for i in range(1, self.N):
            aggregated_message = aggregated_message + self.c1[i]
        decrypt_message = self.rlwe.decrypt(aggregated_message, self.A, self.s)
        return decrypt_message

    def verify_s_key(self, ts):
        print("Aggregator verify users' secret keys")
        aggregated_message = self.c2[0]
        for i in range(1, self.N):
            aggregated_message = aggregated_message + self.c2[i]
        zero = Rq(np.zeros(self.n), self.t)

        encrypted_s = self.rlwe.encrypt(zero, self.A_other, self.s)
        verify_message = self.rlwe.decrypt(encrypted_s-aggregated_message, self.A_other, zero)
        error = "secret key is correct"
        if verify_message.poly.any() != 0:
            error ="\x1b[31msecret key is incorrect\x1b[0m"
        return error


    def sigma_protocol_init(self, t1, t2):
        self.key_WFP = WFP.KeyWellformednessVerify(t1, t2, self.q,self.n, self.t, self.s, self.rlwe, self.NIZK)
        return self.key_WFP.c

    def sigma_protocol_verify(self, i, S_s, S_x, S_e):
        result = self.key_WFP.verify(self.A, self.A_other, S_s, S_x, S_e, self.c1[i], self.c2[i])
        return result

    def L_infry_protocol_init(self, L):
        self.LIN_Verify = LIN.LInftyNormVerify(L, self.q,self.n, self.t, self.s, self.rlwe, self.B_I, self.NIZK)
        return self.LIN_Verify.c

    def L_infry_protocol_verify(self, i, S_s, S_x, S_e):
        result = self.LIN_Verify.verify(self.A, S_s, S_x, S_e, self.c1[i])
        return result

    def L_2_protocol_init(self, t_1, t_2, t_mult, t_plus, c_plus, c_mult, t_wave, c_2):
        self.L2N_Verify = L2N.L2NormVerify(t_1, t_2, t_mult, t_plus, c_plus, c_mult, t_wave, c_2, self.q,self.n, self.t, self.s, self.rlwe, self.B_2, self.NIZK)
        return self.L2N_Verify.c

    def L_2_protocol_verify(self, i, S_x_1, S_x_2, S_x_mult, S_x_plus, S_s_1, S_s_2, S_s_mult, S_s_plus, S_e_1, S_e_2, S_e_mult, S_e_plus, S_s_wave, S_e_wave):
        result = self.L2N_Verify.verify(self.A, S_x_1, S_x_2, S_x_mult, S_x_plus, S_s_1, S_s_2, S_s_mult, S_s_plus, S_e_1, S_e_2, S_e_mult, S_e_plus, S_s_wave, S_e_wave, self.c1[i])
        return result

    def cos_protocol_init(self, c_list_XX, t_list_XX, t_w_XX, c_list_XY, t_list_XY, t_w_XY, X_RP, S_RP):
        self.XX_verify = cos.XXWellformednessVerify(c_list_XX, t_list_XX, t_w_XX, self.q,self.n, self.t, self.s, self.rlwe, self.beta, self.NIZK)
        self.XY_verify = cos.XYWellformednessVerify(self.y, c_list_XY, t_list_XY, t_w_XY, self.q,self.n, self.t, self.s, self.rlwe, self.NIZK)
        self.RP_verify = cos.RangeVerify(X_RP, S_RP, c_list_XY[2] - c_list_XX[1],  self.q,self.n, self.t, self.s, self.rlwe, self.NIZK)

        return self.XX_verify.c, self.XY_verify.c, self.RP_verify.b, self.RP_verify.z

    def cos_protocol_verify(self, S_s_list_xx, S_x_list_xx, S_e_list_xx, S_s_w_xx, S_e_w_xx,
                            S_s_list_xy, S_x_list_xy, S_e_list_xy, S_s_w_list_xy, S_e_w_list_xy,
                            T_list_rp):
        result_xx = self.XX_verify.verify(self.A, S_s_list_xx, S_x_list_xx, S_e_list_xx, S_s_w_xx, S_e_w_xx)
        result_xy = self.XY_verify.verify(self.A, S_s_list_xy, S_x_list_xy, S_e_list_xy, S_s_w_list_xy, S_e_w_list_xy)
        self.RP_verify.challenge2(T_list_rp)
        return result_xx, result_xy, self.RP_verify.x

    def cos_range_verify(self, L_x, R_x, E_x, t_hat, tau_x, T_e):
        result_rp = self.RP_verify.verify(self.A, L_x, R_x, E_x, t_hat, tau_x, T_e)
        return result_rp