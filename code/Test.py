import numpy as np
import RLWE
import Ring_polynomial
import well_formedness_proof as WFP
if __name__ == '__main__':
    n = 8 # power of 2
    q = 67108289  # prime number, q = 1 (mod 2n)
    t = 37  # prime number, t < q
    std = 3  # standard deviation of Gaussian distribution
    ts = 1
    d = 8
    while n < d:
        n = n * 2
    rlwe = RLWE.RLWE(n, q, t, std)
    pub = rlwe.generate_public_keys(ts)
    pub2 = rlwe.generate_public_keys(ts+1)
    sec = rlwe.generate_secret_keys(ts)

    p0 = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
    p1 = [2, 2, 2, 2, 2, 2, 2, 2, 2, 2]
    s = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
    pub = Ring_polynomial.Rq(p0, q)
    pub2 = Ring_polynomial.Rq(p1, q)
    sec = Ring_polynomial.Rq(s, q)

    mm0 = [10,10,10,10,10,10,10,10,10,10]
    mm1 = [0,0,0,0,0,0,0,0,0,0]

    if n > d:
        m0 = Ring_polynomial.Rq(np.hstack((mm0, np.zeros(n-d))), t)
        m1 = Ring_polynomial.Rq(np.hstack((mm1, np.zeros(n - d))), t)
    else:
        m0 = Ring_polynomial.Rq(mm0, t)  # plaintext
        m1 = Ring_polynomial.Rq(mm1, t)  # plaintext

    e0 = [1,1,1,1,1,1,1,1,1,1]
    e1 = [2,2,2,2,2,2,2,2,2,2]

    e = Ring_polynomial.Rq(e0, q)
    e_other = Ring_polynomial.Rq(e1, q)

    #e = RLWE.discrete_gaussian(n, q, ts, std=std)
    #e_other = RLWE.discrete_gaussian(n, q, ts+1, std=std)

    c0 = rlwe.encrypt(m0, pub,sec, e)
    c1 = rlwe.encrypt(m1, pub2,sec, e_other)

    m_0 = rlwe.decrypt(c0, pub,sec)
    m_1 = rlwe.decrypt(c1, pub2,sec)

    print()

    ss_c = [100, 100, 100, 100, 100, 100, 100, 100, 100, 100]
    mm_c = [1100, 1100, 1100, 1100, 1100, 1100, 1100, 1100, 1100, 1100]
    etaa = [3, 3, 3, 3, 3, 3, 3, 3, 3, 3]
    etaa_c = [4, 4, 4, 4, 4, 4, 4, 4, 4, 4]
    s_c = Ring_polynomial.Rq(ss_c, q)
    m_c = Ring_polynomial.Rq(mm_c, q)
    eta = Ring_polynomial.Rq(etaa, q)
    eta_c = Ring_polynomial.Rq(etaa_c, q)
    zero = Ring_polynomial.Rq(np.zeros(n), t)

    t1 = rlwe.encrypt(m_c, pub, s_c, e=eta)
    t2 = rlwe.encrypt(zero, pub2, s_c, e=eta_c)


    #(t1, t2), (s_c, m_c, eta, eta_c) = WFP.sigma_protocol_init(rlwe, pub, pub2)


    #challenge = WFP.sigma_protocol_challenge(q)

    challenge = 10

    S_m = m_c + challenge * m0  # 这里使用简单的标量乘法模拟 RLWE 中的运算
    S_s = s_c + challenge * sec
    S_e = t * (eta_c + eta) +t * challenge * (e + e_other)

    lhs = (pub + pub2) * S_s + S_m + S_e

    rhs = t1 + t2 + challenge * (c0 + c1)


    verify = rlwe.decrypt(rhs -lhs, pub, zero)

    if verify.poly.coeffs == 0:
        result = True
    else:
        result = False

    if result == True:
        print("User {}'s secret key has well-formedness".format(1))
    else:
        print("User {}'s secret key is wrong".format(1))
