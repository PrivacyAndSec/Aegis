from precomputed_powers import POWERS_OF_TWO
import numpy as np
def find_minimum_polynomials(message_dim):
    """
    找到覆盖给定维度消息的最少数量的多项式。

    :param message_dim: 消息的维度。
    :return: 2的幂次列表，表示所选多项式的次数。
    """
    powers_of_two = [2**i for i in range(int(np.log2(message_dim)) + 1)][::-1]
    remaining_dim = message_dim
    selected_powers = []

    for power in powers_of_two:
        if power <= remaining_dim:
            selected_powers.append(power)
            remaining_dim -= power

    return selected_powers


def split_message(message, poly_degrees):
    """
    将消息分割成多个部分，每部分对应一个多项式。

    :param message: 要编码的消息，一个 numpy 数组。
    :param poly_degrees: 每个多项式的次数列表。
    :return: 分割后的消息列表，每个元素是一个 numpy 数组。
    """
    if sum(poly_degrees) < len(message):
        raise ValueError("多项式的次数之和必须大于或等于消息的维度")

    splits = []
    start = 0
    for degree in poly_degrees:
        end = start + degree
        splits.append(message[start:end])
        start = end

    return splits

message_dim = 123  # 消息的维度
selected_powers = find_minimum_polynomials(message_dim)
print("所选多项式的次数:", selected_powers)