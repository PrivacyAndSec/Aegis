import time
import numpy as np
from Ring_polynomial import Rq
def elgamal_commit(p, g, h, w, r):
    """
  ElGamal承诺方案的简化实现。

  参数:
  - p: 大质数。
  - g: p的原根。
  - w: 要承诺的明文元素。
  - r: 密钥（随机数）。

  返回:
  - 承诺值c。
  """
    # 计算承诺
    c = pow(g, w, p) * pow(h, r, p) % p
    c2 = pow(h, w, p)
    return c, c2


# 示例参数
p = 671082891   # 仅示例，实际应用中应选择更大的质数
g = 211111  # p的原根，示例值
h = 111111
n = 2**15
upper_bound = 2147483647
down_bound = 111111111
# 生成随机数
w = np.random.randint(low=down_bound, high=upper_bound + 1, size=n, dtype=np.int64)
r = np.random.randint(low=down_bound, high=upper_bound + 1, size=n, dtype=np.int64)
start_time = time.time()
# 对每个元素进行ElGamal承诺
commitments = [elgamal_commit(p, g, h, int(wi), int(ri)) for wi, ri in zip(w, r)]
end_time = time.time()

time_s = end_time - start_time
print(time_s)

