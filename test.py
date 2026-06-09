from itertools import combinations
from math import comb


def get_ith_combination(n, k, i):
    result = []
    while k > 0:
        n -= 1
        while comb(n, k) > i:
            n -= 1
        result.append(n + 1)
        i -= comb(n, k)
        k -= 1
    return result[::-1]


test_cases = [
    (1, 1, 0),
    (10, 2, 10),
    (10, 5, 10),
    (13, 7, 6),
    (2, 1, 1),
    (3, 2, 1),
    (5, 3, 0),
    (5, 3, 10),
    (5, 3, 2),
    (5, 3, 5),
    (6, 3, 5),
    (7, 2, 10),
    (7, 5, 3),
    (8, 3, 10),
    (8, 5, 10),
]

for n, k, i in test_cases:
    print(f"combinadic({n}, {k}, {i}) = {get_ith_combination(n, k, i)}")
