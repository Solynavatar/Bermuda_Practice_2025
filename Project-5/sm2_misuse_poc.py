#!/usr/bin/env python3
# sm2_misuse_poc.py

import hashlib
import random
import sys

# --------------------
# 曲线参数
# --------------------
p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
a = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
b = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
G = (Gx, Gy)

# Infinity as None
INFINITY = None

# --------------------
# 工具函数
# --------------------
def modinv(x, m=n):
    """计算 x 在模 m 下的乘法逆元。若不存在则抛出 ValueError。"""
    x %= m
    if x == 0:
        raise ValueError("inverse does not exist")
    return pow(x, -1, m)

def int_from_sha256(*parts):
    """把若干部分连接后做 SHA256，返回整数（模 n 之外的 caller 可自行取模）。"""
    h = hashlib.sha256()
    for part in parts:
        if isinstance(part, int):
            h.update(part.to_bytes((part.bit_length() + 7) // 8 or 1, "big"))
        elif isinstance(part, bytes):
            h.update(part)
        else:
            h.update(str(part).encode())
    return int.from_bytes(h.digest(), "big")

# --------------------
# 椭圆曲线点运算（Weierstrass 曲线 y^2 = x^3 + a x + b, 在有限域 F_p 上）
# 使用 None 表示无穷远点
# --------------------
def is_infinity(P):
    return P is None

def point_add(P, Q):
    if is_infinity(P):
        return Q
    if is_infinity(Q):
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2:
        # P + (-P) = O
        if (y1 + y2) % p == 0:
            return INFINITY
        # P == Q 的加法（点翻倍）
        denom = (2 * y1) % p
        if denom == 0:
            return INFINITY
        lam = (3 * x1 * x1 + a) * modinv(denom, p) % p
    else:
        denom = (x2 - x1) % p
        if denom == 0:
            return INFINITY
        lam = ((y2 - y1) * modinv(denom, p)) % p
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)

def scalar_mult(k, P):
    """标准二进制法点乘 k*P。"""
    if k % n == 0 or P is INFINITY:
        return INFINITY
    if k < 0:
        # 负标量: k*P = -(-k*P)
        return scalar_mult(-k, (P[0], (-P[1]) % p))
    R = INFINITY
    addend = P
    while k:
        if k & 1:
            R = point_add(R, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return R

def scalar_mult_window(k, P, window=4):
    """简单窗口法（4-bit 窗口），用于基点或任意点的加速。"""
    if k == 0 or P is INFINITY:
        return INFINITY
    base = 1 << window
    # 预计算 1..(base-1) 倍
    table = [INFINITY] * base
    table[1] = P
    for i in range(2, base):
        table[i] = point_add(table[i - 1], P)
    # 将 k 写成 base 进制
    digits = []
    kk = k
    while kk:
        digits.append(kk % base)
        kk //= base
    R = INFINITY
    for d in reversed(digits):
        # R *= base  (即做 window 次二倍)
        for _ in range(window):
            R = point_add(R, R)
        if d:
            R = point_add(R, table[d])
    return R

# --------------------
# 简化的 SM2 / ECDSA 签名 / 验证（PoC 目的）
# 注意：真实 SM2 有更多的细节（如 ZA 的计算、r/s 的边界重签等），本 PoC 为演示漏洞数学关系
# --------------------
def pub_from_priv(d):
    return scalar_mult(d, G)

def compute_e(pub, M):
    # 将公钥坐标和消息结合：e = H(Z_A || M)
    if pub is INFINITY:
        za = b""  # 不可能，但作保护
    else:
        za = pub[0].to_bytes((pub[0].bit_length() + 7) // 8 or 1, "big") + pub[1].to_bytes((pub[1].bit_length() + 7) // 8 or 1, "big")
    val = int_from_sha256(za, M)
    return val % n

def sign_sm2_with_k(k, d, M):
    """使用给定的 k、私钥 d 和消息 M 返回 SM2 签名 (r, s) 以及中间量 e 和 x1（用于 PoC）"""
    P = scalar_mult(k, G)
    if P is INFINITY:
        raise RuntimeError("k*G = O")
    x1 = P[0] % n
    pub = pub_from_priv(d)
    e = compute_e(pub, M)
    r = (e + x1) % n
    if r == 0 or r + k % n == 0:
        # 实际 SM2 要求重新选 k，但在 PoC 中跳过重签。
        pass
    inv_1pd = modinv((1 + d) % n, n)
    s = ((k - r * d) * inv_1pd) % n
    return (r, s, e, x1)

def verify_sm2(pub, M, sig):
    r, s = sig
    if not (1 <= r <= n - 1 and 1 <= s <= n - 1):
        return False
    e = compute_e(pub, M)
    t = (r + s) % n
    X = point_add(scalar_mult(s, G), scalar_mult(t, pub))
    if X is INFINITY:
        return False
    x1p = X[0] % n
    R = (e + x1p) % n
    return R == r

def sign_ecdsa_with_k(k, d, M):
    """极简 ECDSA-like 签名（PoC），r = x1 mod n, s = k^{-1} (e + d*r) mod n"""
    P = scalar_mult(k, G)
    if P is INFINITY:
        raise RuntimeError("k*G = O")
    r = P[0] % n
    e = int_from_sha256(M) % n
    s = (modinv(k, n) * ((e + d * r) % n)) % n
    return (r, s, e)

# --------------------
# 各场景 PoC 函数
# --------------------
def poc_known_k_recovers_d():
    print("--- PoC1: 已知 k 恢复 d ---")
    k = random.randrange(1, n)
    d = random.randrange(1, n)
    M = b"message-1"
    r, s, e, x1 = sign_sm2_with_k(k, d, M)
    print("k", hex(k))
    print("r", hex(r), "s", hex(s))
    d_rec = ((k - s) * modinv((r + s) % n, n)) % n
    print("真实 d:", hex(d))
    print("恢复 d:", hex(d_rec))
    assert d == d_rec
    print("恢复成功\n")

def poc_reuse_k_same_priv():
    print("--- PoC2: 同一私钥复用 k 在不同消息上泄露 d ---")
    k = random.randrange(1, n)
    d = random.randrange(1, n)
    M1 = b"msg-A"
    M2 = b"msg-B"
    r1, s1, e1, x11 = sign_sm2_with_k(k, d, M1)
    r2, s2, e2, x12 = sign_sm2_with_k(k, d, M2)
    print("k", hex(k))
    print("r1,s1", hex(r1), hex(s1))
    print("r2,s2", hex(r2), hex(s2))
    num = (s1 - s2) % n
    den = ((s2 + r2) - (s1 + r1)) % n
    d_rec = (num * modinv(den, n)) % n
    print("真实 d:", hex(d))
    print("恢复 d:", hex(d_rec))
    assert d == d_rec
    print("恢复成功\n")

def poc_shared_k_two_users_known_one_priv():
    print("--- PoC3: 两用户共享 k，已知 A 的私钥可恢复 B 的私钥 ---")
    k = random.randrange(1, n)
    dA = random.randrange(1, n)
    dB = random.randrange(1, n)
    rA, sA, _, _ = sign_sm2_with_k(k, dA, b"A")
    rB, sB, _, _ = sign_sm2_with_k(k, dB, b"B")
    print("rA,sA", hex(rA), hex(sA))
    print("rB,sB", hex(rB), hex(sB))
    # 已知 dA 恢复 k
    k_rec = (sA + dA * ((sA + rA) % n)) % n
    dB_rec = ((k_rec - sB) * modinv((rB + sB) % n, n)) % n
    print("真实 dB:", hex(dB))
    print("恢复 dB:", hex(dB_rec))
    assert dB == dB_rec
    print("恢复成功\n")

def poc_malleability_demo():
    print("--- PoC4: 可塑性展示 (r, s) 与 (r, -s) ---")
    d = random.randrange(1, n)
    pub = pub_from_priv(d)
    k = random.randrange(1, n)
    r, s, _, _ = sign_sm2_with_k(k, d, b"malleability")
    print("原签名验证:", verify_sm2(pub, b"malleability", (r, s)))
    s_mal = (-s) % n
    print("伪造 (r, -s) 验证:", verify_sm2(pub, b"malleability", (r, s_mal)))
    # canonicalize: s' = min(s, n-s)
    s_canonical = s if s <= n // 2 else (-s) % n
    print("规一化 s 后的 s':", hex(s_canonical))
    print("验签 (r, s_canonical):", verify_sm2(pub, b"malleability", (r, s_canonical)))
    print()

def poc_broken_verifier_accepts_wrong_message():
    print("--- PoC5: 错误的验证器（信任外部 e）导致消息替换 ---")
    d = random.randrange(1, n)
    pub = pub_from_priv(d)
    k = random.randrange(1, n)
    r, s, e, _ = sign_sm2_with_k(k, d, b"original")
    # broken_verify 接受 (r,s,e) 并使用外部的 e，而不是重新计算 Hash(Z||M)
    def broken_verify(pub, M, r, s, e_provided):
        t = (r + s) % n
        X = point_add(scalar_mult(s, G), scalar_mult(t, pub))
        if X is INFINITY:
            return False
        R = (e_provided + X[0]) % n
        return R == r
    print("坏验证器对 original 验签:", broken_verify(pub, b"original", r, s, e))
    print("坏验证器对 new_message 验签（将 same e 再用在不同消息上）:", broken_verify(pub, b"new_message", r, s, e))
    print()

def poc_cross_protocol_reuse_k():
    print("[跨协议 k 复用攻击 PoC]")

    d = random.randrange(1, n)
    P = scalar_mult(d, G)

    k = random.randrange(1, n)
    e_ecdsa = random.randrange(1, n)

    # 计算 r
    x1, _ = scalar_mult(k, G)
    r = (x1 % n)

    # ECDSA 签名
    s_ecdsa = (pow(k, -1, n) * (e_ecdsa + r * d)) % n

    # SM2 签名
    s_sm2 = ((pow(1 + d, -1, n)) * (k - r * d)) % n

    # 恢复私钥
    numerator = (s_sm2 * s_ecdsa - e_ecdsa) % n
    denominator = (r - (s_sm2 + r) * s_ecdsa) % n
    d_rec = (numerator * pow(denominator, -1, n)) % n

    print(f"原始私钥 d: {d}")
    print(f"恢复私钥 d_rec: {d_rec}")
    assert d == d_rec
    print("恢复成功\n")


# --------------------
# 主函数：依次运行 PoC 场景
# --------------------
def main():
    random.seed(42)
    poc_known_k_recovers_d()
    poc_reuse_k_same_priv()
    poc_shared_k_two_users_known_one_priv()
    poc_malleability_demo()
    poc_broken_verifier_accepts_wrong_message()
    poc_cross_protocol_reuse_k()

if __name__ == '__main__':
    main()
