from sympy import nextprime

def find_prime_congruent_to_one(modulus):
    candidate = modulus
    while True:
        prime = nextprime(candidate)
        if prime % modulus == 1:
            return prime
        candidate = prime

# 示例：假设 n 是 2 的 10 次方
n = 2**10
modulus = 2 * n
prime = find_prime_congruent_to_one(modulus)
print(f"The prime number q = {prime} is congruent to 1 (mod {modulus}).")
