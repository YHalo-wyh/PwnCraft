#!/usr/bin/env python3

import random
from sympy import nextprime
from gmpy2 import is_prime
from Crypto.Util.number import getPrime, bytes_to_long
from Secret import flag

m = bytes_to_long(flag)

p = getPrime(1024)
q = getPrime(1024)
n = p * q
e = 2999

f = open("out.txt", 'w')

p1 = getPrime(1024)
q1 = nextprime(2024 * p1)
n1 = p1 * q1
f.write("n1 = {0}\n".format(n1))

p2 = getPrime(1024)
q2 = 1
while q2 < p2:
    q2 = getPrime(1024)
n2 = p2 * q2
n22 = p2 * p2 + q2 * q2
f.write("n2 = {0}\n".format(n2))
f.write("n22 = {0}\n".format(n22))

r = random.getrandbits(1024)
p3 = r
while not is_prime(p3):
    p3 += random.getrandbits(400)
q3 = r
while q3 < p3:
    q3 += random.getrandbits(500)
while not is_prime(p3):
    q3 += random.getrandbits(500)
n3 = p3 * q3
f.write("n3 = {0}\n".format(n3))

m1 = p1 * m * m + p2 * m + p3
m2 = q1 * m * m + q2 * m + q3
c1 = pow(m1, e, n)
c2 = pow(m2, e, n)

f.write("n = {0}\n".format(n))
f.write("c1 = {0}\n".format(c1))
f.write("c2 = {0}\n".format(c2))
