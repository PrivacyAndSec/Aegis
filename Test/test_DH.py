import random
import math
import time


def generate_pg():
    p = 671082891  # 模数，简化示例仍使用静态值
    g = 37  # 基数
    return p, g


def generate_keys(p, g):
    private_key = random.randint(1, p - 1)
    public_key = pow(g, private_key, p)
    return private_key, public_key


def compute_shared_key(private_key, other_public_key, p):
    shared_key = pow(other_public_key, private_key, p)
    return shared_key


def simulate_dh_key_exchange(N, d):
    p, g = generate_pg()
    # 生成所有用户的私钥和公钥列表，每个用户d个公钥对应d维
    keys = [[generate_keys(p, g) for _ in range(d)] for _ in range(N)]

    # 初始化共享密钥字典
    shared_keys = {}

    for i in range(N):
        num_to_share = max(1, math.ceil(math.log2(N)))  # 确保至少选择一个用户
        available_users = list(range(N))
        available_users.remove(i)  # 移除当前用户
        selected_users = random.sample(available_users, min(num_to_share, len(available_users)))

        for j in selected_users:
            # 对于每个维度，单独计算共享密钥
            shared_key_vector = []
            for dim in range(d):
                shared_key = compute_shared_key(keys[i][dim][0], keys[j][dim][1], p)
                shared_key_vector.append(shared_key)

            # 使用向量作为共享密钥
            shared_keys[(i, j)] = shared_key_vector
            shared_keys[(j, i)] = shared_key_vector  # 确保双向共享相同密钥

    return shared_keys


N = 100
d = 2**13
start = time.time()
shared_keys = simulate_dh_key_exchange(N, d)
end = time.time()

print(end - start)