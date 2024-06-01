import numpy as np
import sys
from Aggregator import Aggregator
from User import User
from RLWE import RLWE
import time
import os
from latency import simulate_network_conditions
def main(config):
    # 用户数量和数据维度
    if os.path.exists(config.time_result_path):
        os.remove(config.time_result_path)
    if os.path.exists(config.space_result_path):
        os.remove(config.space_result_path)

    n = config.n  # power of 2
    q = config.q  # prime number, q = 1 (mod 2n)
    t = config.t  # prime number, t < q
    std = config.std  # standard deviation of Gaussian distribution
    ts = config.ts # timestamp
    d = config.d # message dimension
    N = config.N # User number
    NIZK = config.NIZK
    B_I = config.B_I
    B_2 = config.B_2
    K = config.K
    y = config.y
    alpha = config.alpha
    beta = int(alpha * alpha * np.sum(y * y))
    latency_s = config.latency_s
    bandwidth_mbps = config.bandwidth_mbps

    while n < d:
        n = n * 2
    print("Polynomial dimension: {}, Message dimension: {}, User number: {}, NIZK: {}, Latency: {}s, Bandwidth: "
          "{}mbps".format(n, d, N, NIZK, latency_s, bandwidth_mbps))
    print("===================================================================")
    print("Start of clock")
    print("===================================================================")
    print("Start of initialization")

    #time_star = time.time()
    rlwe = RLWE(n, q, t, std)
    # 创建聚合器
    aggregator = Aggregator(rlwe, N, d, n, t, q, B_I,B_2, NIZK, y=y, beta=beta)
    aggregator.update_A(ts)
    aggregator.updata_A_other(ts)

    # 创建用户
    users = [User(i, n, rlwe, t, n, q, d, B_I, B_2, NIZK, beta=beta, y=y) for i in range(N)]


    print("End of initialization")

    for k in range(0, K):

        # 创建用户并发送加密数据
        time_Encrypt_message = 0
        time_Encrpyt_message_with_transmission = 0
        Total_Encrypt_message_size = 0
        x_aggregation = None
        for i in range(N):
            users[i].update_A(ts)
            users[i].update_s(ts)
            users[i].generate_data()
            if x_aggregation == None:
                x_aggregation = users[i].x
            else:
                x_aggregation = x_aggregation + users[i].x
            #加密时间
            time_start = time.time_ns()
            encrypted_x = users[i].encrypted_message(ts)
            time_end = time.time_ns()
            time_Encrypt_message = time_Encrypt_message + time_end - time_start

            #传输密文时间
            time_start = time.time_ns()
            sizeof_encrypted_x = simulate_network_conditions(encrypted_x, latency_s, bandwidth_mbps)
            aggregator.receive_c1(encrypted_x)
            time_end = time.time_ns()
            Total_Encrypt_message_size = Total_Encrypt_message_size + sizeof_encrypted_x
            time_Encrpyt_message_with_transmission = time_Encrpyt_message_with_transmission + time_end - time_start

            aggregator.compute_s_key(users[i].s)


        time_start = time.time_ns()
        aggregated_data = aggregator.aggregate_data()

        time_end = time.time_ns()
        result = np.array_equal(aggregated_data.poly, x_aggregation.poly)
        if result is False:
            print("\x1b[31mDecrypt False\x1b[0m")
        time_Aggregation_Decrypt = time_end - time_start


        print("SLAP is over\nRLPA begin")

        print("Verify secret keys")


        time_Encrypt_key = 0
        time_Encrypt_key_with_transmission = 0
        Total_Encrypt_key_size = 0
        for i in range(N):
            users[i].updata_A_other(ts)
            time_start = time.time_ns()
            encrypted_s = users[i].encrypted_s(ts)
            time_end = time.time_ns()
            time_Encrypt_key = time_Encrypt_key + time_end - time_start

            time_start = time.time_ns()
            sizeof_encrypted_s = simulate_network_conditions(encrypted_s, latency_s, bandwidth_mbps)
            aggregator.receive_c2(encrypted_s)
            time_end = time.time_ns()
            Total_Encrypt_key_size = Total_Encrypt_key_size + sizeof_encrypted_s
            time_Encrypt_key_with_transmission = time_Encrypt_key_with_transmission + time_end - time_start

        time_Verify_key = 0
        time_start = time.time_ns()
        result = aggregator.verify_s_key(ts)
        print(result)
        time_end = time.time_ns()
        time_Verify_key = time_Verify_key + time_end - time_start
        print("Secret keys verified")

        time_WFP_Proof = 0
        time_WFP_with_transmission = 0
        Total_WFP_Proof_size = 0
        time_WFP_challenge_transimission = 0
        Total_WFP_challenge_size = 0
        time_BF_key = 0
        time_BF_key_transimission = 0
        Total_BF_key_size = 0
        time_verify_WFP = 0
        NIZK_L2N_Proof_size = 0
        NIZK_LIN_Proof_size = 0
        NIZK_WFP_Proof_size = 0
        print("Verify well-formedness proof of secret keys")
        #证明c1和c2中所使用的私钥s是同一个
        for i in range(N):
            time_start = time.time_ns()
            key_WFP = users[i].sigma_protocol_init()
            time_end = time.time_ns()
            time_WFP_Proof = time_WFP_Proof + time_end - time_start

            time_start = time.time_ns()
            WFP_Proof_size = simulate_network_conditions((key_WFP.t1.poly, key_WFP.t2.poly), latency_s, bandwidth_mbps)
            time_end = time.time_ns()
            Total_WFP_Proof_size = Total_WFP_Proof_size + WFP_Proof_size
            time_WFP_with_transmission = time_WFP_with_transmission + time_end - time_start
            WFP_challenge = aggregator.sigma_protocol_init(key_WFP.t1, key_WFP.t2)
            if NIZK is True:
                WFP_challenge = key_WFP.challenge

            time_start = time.time_ns()
            WFP_challenge_size = simulate_network_conditions(WFP_challenge, latency_s, bandwidth_mbps)
            time_end = time.time_ns()
            Total_WFP_challenge_size = Total_WFP_challenge_size + WFP_challenge_size
            time_WFP_challenge_transimission = time_WFP_challenge_transimission + time_end - time_start

            time_start = time.time_ns()
            S_s, S_x, S_e = users[i].sigma_protocol_response(WFP_challenge)
            time_end = time.time_ns()
            time_BF_key = time_BF_key + time_end - time_start

            time_start = time.time_ns()
            BF_key_size = simulate_network_conditions((S_s.poly, S_x.poly, S_e.poly), latency_s, bandwidth_mbps)
            time_end = time.time_ns()
            Total_BF_key_size = Total_BF_key_size + BF_key_size
            time_BF_key_transimission = time_BF_key_transimission + time_end - time_start

            time_start = time.time_ns()
            result = aggregator.sigma_protocol_verify(i, S_s, S_x, S_e)
            time_end = time.time_ns()
            time_verify_WFP = time_verify_WFP + time_end - time_start
            if NIZK is True:
                NIZK_WFP_Proof_size = NIZK_WFP_Proof_size + sys.getsizeof((aggregator.c2[i].poly, key_WFP.t1.poly, key_WFP.t2.poly, S_s.poly, S_x.poly, S_e.poly))
            if result == False:
                print("\x1b[31mUser {}'s secret key is wrong\x1b[0m".format(i))
        Key_computation = time_Encrypt_key + time_WFP_Proof + time_BF_key
        Key_verify = time_Verify_key + time_verify_WFP


        time_LIN_Proof = 0
        time_LIN_with_transmission = 0
        Total_LIN_Proof_size = 0
        time_LIN_challenge_transimission = 0
        Total_LIN_challenge_size = 0
        time_BF_LIN = 0
        time_BF_LIN_transimission = 0
        Total_BF_LIN_size = 0
        time_verify_LIN = 0
        #证明c1当中的m是在范数界限L2和L无穷当中。
        print("Verify L infinite norm bound of message")
        for i in range(N):
            #首先证明m的无穷范数。
            time_start = time.time_ns()
            LIN_Proof = users[i].L_infry_protocol_init()
            time_end = time.time_ns()
            time_LIN_Proof = time_LIN_Proof + time_end - time_start

            time_start = time.time_ns()
            LIN_Proof_size = simulate_network_conditions(LIN_Proof.L.poly, latency_s, bandwidth_mbps)
            time_end = time.time_ns()
            Total_LIN_Proof_size = Total_LIN_Proof_size + LIN_Proof_size
            time_LIN_with_transmission = time_LIN_with_transmission + time_end - time_start

            LIN_challenge = aggregator.L_infry_protocol_init(LIN_Proof.L)
            if NIZK is True:
                LIN_challenge = LIN_Proof.challenge

            time_start = time.time_ns()
            LIN_challenge_size = simulate_network_conditions(LIN_challenge, latency_s, bandwidth_mbps)
            time_end = time.time_ns()
            Total_LIN_challenge_size = Total_LIN_challenge_size + LIN_challenge_size
            time_LIN_challenge_transimission = time_LIN_challenge_transimission + time_end - time_start

            time_start = time.time_ns()
            S_s, S_x, S_e = users[i].L_Infty_Norm_response(LIN_challenge)
            time_end = time.time_ns()
            time_BF_LIN = time_BF_LIN + time_end -time_start

            time_start = time.time_ns()
            BF_LIN_size = simulate_network_conditions((S_s.poly, S_x.poly, S_e.poly), latency_s, bandwidth_mbps)
            time_end = time.time_ns()
            Total_BF_LIN_size = Total_BF_LIN_size + BF_LIN_size
            time_BF_LIN_transimission = time_BF_LIN_transimission + time_end - time_start

            time_start = time.time_ns()
            result = aggregator.L_infry_protocol_verify(i, S_s, S_x, S_e)
            time_end = time.time_ns()
            time_verify_LIN = time_verify_LIN + time_end - time_start

            if config.NIZK is True:
                NIZK_LIN_Proof_size = NIZK_LIN_Proof_size + sys.getsizeof((LIN_Proof.L.poly, S_s.poly, S_x.poly, S_e.poly))

            if result != "correct":
                print("\x1b[31mUser {}'s message: {}\x1b[0m".format(i, result))
        LIN_computation = time_LIN_Proof + time_BF_LIN
        LIN_verify = time_verify_LIN

        #证明m的二次范数
        time_L2N_Proof = 0
        time_L2N_with_transmission = 0
        Total_L2N_Proof_size = 0
        time_L2N_challenge_transimission = 0
        Total_L2N_challenge_size = 0
        time_BF_L2N = 0
        time_BF_L2N_transimission = 0
        Total_BF_L2N_size = 0
        time_verify_L2N = 0
        print("Verify L2 norm bound of message")
        for i in range(N):
            time_start = time.time_ns()
            L2N_Proof = users[i].L_2_protocol_init()
            time_end = time.time_ns()
            time_L2N_Proof = time_L2N_Proof + time_end - time_start

            time_start = time.time_ns()
            L2N_Proof_size = simulate_network_conditions((L2N_Proof.t_1.poly, L2N_Proof.t_2.poly, L2N_Proof.t_mult.poly,
                                L2N_Proof.t_plus.poly, L2N_Proof.c_plus.poly, L2N_Proof.c_mult.poly, L2N_Proof.t_wave.poly, L2N_Proof.c_2.poly), latency_s, bandwidth_mbps)
            time_end = time.time_ns()
            Total_L2N_Proof_size = Total_L2N_Proof_size + L2N_Proof_size
            time_L2N_with_transmission = time_L2N_with_transmission + time_end - time_start

            L2N_challenge = aggregator.L_2_protocol_init(L2N_Proof.t_1, L2N_Proof.t_2, L2N_Proof.t_mult,
                                L2N_Proof.t_plus, L2N_Proof.c_plus, L2N_Proof.c_mult, L2N_Proof.t_wave, L2N_Proof.c_2)
            if NIZK is True:
                L2N_challenge = L2N_Proof.challenge

            time_start = time.time_ns()
            L2N_challenge_size = simulate_network_conditions(L2N_challenge, latency_s, bandwidth_mbps)
            time_end = time.time_ns()
            Total_L2N_challenge_size = Total_L2N_challenge_size + L2N_challenge_size
            time_L2N_challenge_transimission = time_L2N_challenge_transimission + time_end - time_start

            time_start = time.time_ns()
            (S_x_1, S_x_2, S_x_mult, S_x_plus, S_s_1, S_s_2, S_s_mult,
             S_s_plus, S_e_1, S_e_2, S_e_mult, S_e_plus, S_s_wave, S_e_wave) = users[i].L_2_Norm_response(L2N_challenge)
            time_end = time.time_ns()
            time_BF_L2N = time_BF_L2N + time_end - time_start

            time_start = time.time_ns()
            BF_L2N_size = simulate_network_conditions((S_x_1.poly, S_x_2.poly, S_x_mult.poly, S_x_plus.poly, S_s_1.poly, S_s_2.poly, S_s_mult.poly,
             S_s_plus.poly, S_e_1.poly, S_e_2.poly, S_e_mult.poly, S_e_plus.poly, S_s_wave.poly, S_e_wave.poly), latency_s, bandwidth_mbps)
            time_end = time.time_ns()
            Total_BF_L2N_size = Total_BF_L2N_size + BF_L2N_size
            time_BF_L2N_transimission = time_BF_L2N_transimission + time_end - time_start

            time_start = time.time_ns()
            result = aggregator.L_2_protocol_verify(i, S_x_1, S_x_2, S_x_mult, S_x_plus, S_s_1, S_s_2, S_s_mult, S_s_plus,
                                                    S_e_1, S_e_2, S_e_mult, S_e_plus, S_s_wave, S_e_wave)
            time_end = time.time_ns()
            time_verify_L2N = time_verify_L2N + time_end - time_start
            if config.NIZK is True:
                NIZK_L2N_Proof_size = NIZK_L2N_Proof_size + sys.getsizeof((L2N_Proof.t_1.poly, L2N_Proof.t_2.poly,
                                                                           L2N_Proof.t_mult.poly, L2N_Proof.t_plus.poly,
                                                                           L2N_Proof.c_plus.poly, L2N_Proof.c_mult.poly,
                                                                           L2N_Proof.t_wave.poly, L2N_Proof.c_2.poly,
                                                                           S_x_1.poly, S_x_2.poly, S_x_mult.poly,
                                                                           S_x_plus.poly, S_s_1.poly, S_s_2.poly, S_s_mult.poly,
             S_s_plus.poly, S_e_1.poly, S_e_2.poly, S_e_mult.poly, S_e_plus.poly, S_s_wave.poly, S_e_wave.poly))
            if len(result) > 0:
                for error in result:
                    if error == '1':
                        print("\x1b[31mUser {}: Error in t_1 and c_1\x1b[0m".format(i))
                    elif error == '2':
                        print("\x1b[31mUser {}: Error in t_2 and c_2\x1b[0m".format(i))
                    elif error == 'plus':
                        print("\x1b[31mUser {}: Error in t_plus and c_plus\x1b[0m".format(i))
                    elif error == 'mult':
                        print("\x1b[31mUser {}: Error in t_mult and c_mult\x1b[0m".format(i))
                    elif error == 'wave':
                        print("\x1b[31mUser {}: Error in t_wave and c_wave\x1b[0m".format(i))
                    elif error == 'L2':
                        print("\x1b[31mUser {}: Error in L2 boundry\x1b[0m".format(i))
        L2N_computation = time_L2N_Proof + time_BF_L2N
        L2N_verify = time_verify_L2N

        # Verify Cosine

        time_cos_verify = 0
        time_cos_proof = 0
        space_cos = 0
        IZK_cos = 0
        print("Verify cosine of message")
        for i in range(N):
            time_start = time.time_ns()
            XX_Proof, XY_Proof, Range_Proof = users[i].proof_cosine_init()
            time_end = time.time_ns()
            time_cos_proof = time_cos_proof + time_end - time_start
            message = (XX_Proof.c_list, XX_Proof.t_list, XX_Proof.t_w, XY_Proof.c_list, XY_Proof.t_list,
                       XY_Proof.t_w_list, Range_Proof.X, Range_Proof.S)
            space_cos = space_cos + simulate_network_conditions(message, latency_s, bandwidth_mbps)

            time_start = time.time_ns()
            XX_c, XY_c, RP_b, RP_z = aggregator.cos_protocol_init(XX_Proof.c_list, XX_Proof.t_list, XX_Proof.t_w,
                                                                  XY_Proof.c_list, XY_Proof.t_list, XY_Proof.t_w_list, Range_Proof.X, Range_Proof.S)
            time_end = time.time_ns()
            time_cos_verify = time_cos_verify + time_end - time_start

            message = (XX_c, XY_c, RP_b, RP_z)
            IZK_cos = IZK_cos + simulate_network_conditions(message, latency_s, bandwidth_mbps)

            time_start = time.time_ns()
            S_s_list_xx, S_x_list_xx, S_e_list_xx, S_s_w_xx, S_e_w_xx, \
            S_s_list_xy, S_x_list_xy, S_e_list_xy, S_s_w_list_xy, S_e_w_list_xy, \
            T_list_rp = users[i].cosine_response(XX_c, XY_c, RP_b, RP_z)
            time_end = time.time_ns()
            time_cos_proof = time_cos_proof + time_end - time_start

            message = (S_s_list_xx, S_x_list_xx, S_e_list_xx, S_s_w_xx, S_e_w_xx, S_s_list_xy, S_x_list_xy,
                       S_e_list_xy, S_s_w_list_xy, S_e_w_list_xy, T_list_rp)
            space_cos = space_cos + simulate_network_conditions(message, latency_s, bandwidth_mbps)

            time_start = time.time_ns()
            result_xx, result_xy, x_rp = aggregator.cos_protocol_verify(S_s_list_xx, S_x_list_xx, S_e_list_xx, S_s_w_xx, S_e_w_xx,
                                           S_s_list_xy, S_x_list_xy, S_e_list_xy, S_s_w_list_xy, S_e_w_list_xy,
                                           T_list_rp)
            IZK_cos = IZK_cos + simulate_network_conditions(x_rp, latency_s, bandwidth_mbps)

            time_end = time.time_ns()
            time_cos_verify = time_cos_verify + time_end - time_start

            if result_xx != "correct":
                print("\x1b[31mUser {}'s message: {}\x1b[0m".format(i, result_xx))

            if result_xy != "correct":
                print("\x1b[31mUser {}'s message: {}\x1b[0m".format(i, result_xy))

            time_start = time.time_ns()
            L_x, R_x, E_x, t_hat, tau_x, T_e = users[i].cosine_rp(x_rp)
            time_end = time.time_ns()
            time_cos_proof = time_cos_proof + time_end - time_start

            message = (L_x, R_x, E_x, t_hat, tau_x, T_e)
            space_cos = space_cos + simulate_network_conditions(message, latency_s, bandwidth_mbps)

            time_start = time.time_ns()
            result_rp = aggregator.cos_range_verify(L_x, R_x, E_x, t_hat, tau_x, T_e)
            time_end = time.time_ns()
            time_cos_verify = time_cos_verify + time_end - time_start

            if result_rp != "correct":
                print("\x1b[31mUser {}'s message: {}\x1b[0m".format(i, result_rp))

        time_file = open(config.time_result_path, 'w')

        time_file.writelines("Polynomial dimension: {}, Message dimension: {}, User number: {}, NIZK: {}, Latency: {}s, Bandwidth: "
              "{}mbps\n".format(n, d, N, NIZK, latency_s, bandwidth_mbps))
        time_file.writelines("{}\n".format(time_Encrypt_message))
        time_file.writelines("{},{}\n".format(Key_computation, Key_verify))
        time_file.writelines("{},{}\n".format(LIN_computation, LIN_verify))
        time_file.writelines("{},{}\n".format(L2N_computation, L2N_verify))
        time_file.writelines("{},{}\n".format(time_cos_proof, time_cos_verify))
        time_file.writelines("cos_cost:{}bytes,IZK_cost:{}bytes\n".format(space_cos, IZK_cos))

        """
        time_file.writelines("Encrypt message: {}s, Send Encrypted Message: {}s, Total: {}s\n".format(time_Encrypt_message,
                                                                                                 time_Encrpyt_message_with_transmission,
                                                                                                 time_Encrypt_message + time_Encrpyt_message_with_transmission))
        time_file.writelines("Aggregation and Decrypt: {}s\n".format(time_Aggregation_Decrypt))
        time_file.writelines("Verify Key: {}s\n".format(time_Verify_key))
        time_file.writelines("Generate well-formednesss proof for key:{}s, Send Proofs: {}s, Total: {}s\n".format(time_WFP_Proof,
                                                                                                             time_WFP_with_transmission,
                                                                                                             time_WFP_Proof + time_WFP_with_transmission))
        time_file.writelines("Aggregator send challenge: {}s\n".format(time_WFP_challenge_transimission))
        time_file.writelines("Generate blind factor of key:{}s, Send blind factor: {}s, Total: {}s\n".format(time_BF_key,
                                                                                                        time_BF_key_transimission,
                                                                                                        time_BF_key + time_BF_key_transimission))
        time_file.writelines("Aggregator Verify Well-Foremedness proof: {}s\n".format(time_verify_WFP))
        time_file.writelines("Generate L infinity bound proof for message:{}s, Send Proofs: {}s, Total: {}s\n".format(time_LIN_Proof,
                                                                                                             time_LIN_with_transmission,
                                                                                                             time_LIN_Proof + time_LIN_with_transmission))
        time_file.writelines("Aggregator send challenge: {}s\n".format(time_LIN_challenge_transimission))
        time_file.writelines("Generate blind factor of key:{}s, Send blind factor: {}s, Total: {}s\n".format(time_BF_LIN,
                                                                                                        time_BF_LIN_transimission,
                                                                                                        time_BF_LIN + time_BF_LIN_transimission))
        time_file.writelines("Aggregator Verify L infinity bound proof: {}s\n".format(time_verify_LIN))
        time_file.writelines(
            "Generate L 2 bound proof for message:{}s, Send Proofs: {}s, Total: {}s\n".format(time_L2N_Proof,
                                                                                                time_L2N_with_transmission,
                                                                                                time_L2N_Proof + time_L2N_with_transmission))
        time_file.writelines("Aggregator send challenge: {}s\n".format(time_L2N_challenge_transimission))
        time_file.writelines("Generate blind factor of key:{}s, Send blind factor: {}s, Total: {}s\n".format(time_BF_L2N,
                                                                                                        time_BF_L2N_transimission,
                                                                                                        time_BF_L2N + time_BF_L2N_transimission))
        time_file.writelines("Aggregator Verify 2 infinity bound proof: {}s\n".format(time_verify_LIN))
        time_file.close()
        size_file = open(config.space_result_path, 'w')
        size_file.writelines("Polynomial dimension: {}, Message dimension: {}, User number: {}, NIZK: {}, Latency: {}s, Bandwidth: "
              "{}mbps\n".format(n, d, N, NIZK, latency_s, bandwidth_mbps))
        size_file.writelines("Encrypted message size: {}bytes\n".format(Total_Encrypt_message_size))
        size_file.writelines("Encrypted key size: {}bytes\n".format(Total_Encrypt_key_size))
        



        if config.NIZK is False:
            size_file.writelines("Well-formedness challenge size: {}bytes\n".format(Total_WFP_challenge_size))
            size_file.writelines("Blind factor of WFP size: {}bytes\n".format(Total_BF_key_size))
            size_file.writelines("L infity norm challenge size: {}bytes\n".format(Total_LIN_challenge_size))
            size_file.writelines("Blind factor of LIN size: {}bytes\n".format(Total_BF_LIN_size))
            size_file.writelines("L 2 norm challenge size: {}bytes\n".format(Total_L2N_challenge_size))
            size_file.writelines("Blind factor of L2N size: {}bytes\n".format(Total_BF_L2N_size))
            size_file.writelines("Well-formedness proof size: {}bytes\n".format(Total_WFP_Proof_size))
            size_file.writelines("L infity norm proof size: {}bytes\n".format(Total_LIN_Proof_size))
            size_file.writelines("L 2 norm proof size: {}bytes\n".format(Total_L2N_Proof_size))
        else:
            size_file.writelines("Well-formedness proof size: {}bytes\n".format(NIZK_WFP_Proof_size))
            size_file.writelines("L infity norm proof size: {}bytes\n".format(NIZK_LIN_Proof_size))
            size_file.writelines("L 2 norm proof size: {}bytes\n".format(NIZK_L2N_Proof_size))

        size_file.close()
        """
        print("Finish")

