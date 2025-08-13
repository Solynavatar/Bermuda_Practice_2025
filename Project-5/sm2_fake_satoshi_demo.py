# sm2_fake_satoshi_demo.py
# 受控演示：SM2 重复 k 导致的签名伪造漏洞
# 本示例仅用于安全研究和教学，切勿用于任何真实系统！

from gmssl import sm3, func
from random import randint
from ecdsa import numbertheory, curves

# 使用 NIST P-256 曲线近似模拟 SM2 曲线（仅为演示，非生产）
curve = curves.NIST256p.curve
G = curves.NIST256p.generator
n = G.order()

def H(msg: str) -> int:
    """SM3(message) -> int"""
    return int(sm3.sm3_hash(func.bytes_to_list(msg.encode())), 16)

def sm2_sign(private_key: int, message: str, k: int):
    """
    简化 SM2 签名：
      r = (e + x1) mod n
      s = (k - r*d) * (1 + d)^(-1) mod n
    返回 (r, s)
    """
    e = H(message) % n
    R = k * G
    x1 = R.x() % n
    r = (e + x1) % n
    s = ((k - (r * private_key) % n) * numbertheory.inverse_mod(1 + private_key, n)) % n
    return (r, s)

def sm2_verify(public_key, message: str, sig):
    """极简 SM2 验签"""
    r, s = sig
    if not (1 <= r <= n - 1 and 1 <= s <= n - 1):
        return False
    e = H(message) % n
    t = (r + s) % n
    if t == 0:
        return False
    # X = s*G + t*P
    X = s * G + t * public_key
    if X is None:  # 不太可能
        return False
    R = (e + X.x()) % n
    return R == r

def recover_private_key_from_reused_k(sig1, sig2):
    """
    当同一私钥在不同消息上重复使用同一个 k 时，利用：
      s1(1+d) ≡ k - r1*d
      s2(1+d) ≡ k - r2*d
    相减并整理得到：
      d ≡ (s1 - s2) * ( (r2 - r1) - (s1 - s2) )^(-1) (mod n)
    """
    r1, s1 = sig1
    r2, s2 = sig2
    ds = (s1 - s2) % n
    dr = (r2 - r1) % n
    denom = (dr - ds) % n
    if denom == 0:
        raise ZeroDivisionError("分母为 0：更换消息或 k 重试")
    d = (ds * numbertheory.inverse_mod(denom, n)) % n
    return d

def poc_fake_satoshi_signature():
    print("=== 受控演示：SM2 重复 k 导致的签名伪造漏洞 ===")

    # 1) 生成“假中本聪”密钥
    d_real = randint(1, n - 1)
    P_real = d_real * G
    print(f"[公钥] ({hex(P_real.x())}, {hex(P_real.y())})")

    # 2) 让“假中本聪”用相同 k 签不同消息
    attempts = 0
    while True:
        attempts += 1
        k_reuse = randint(1, n - 1)
        m1 = "I am Satoshi Nakamoto"
        m2 = "I will send you 10 BTC"
        sig1 = sm2_sign(d_real, m1, k_reuse)
        sig2 = sm2_sign(d_real, m2, k_reuse)
        try:
            d_rec = recover_private_key_from_reused_k(sig1, sig2)
            break
        except ZeroDivisionError:
            if attempts > 32:
                raise
            continue

    print(f"[攻击] 恢复的私钥 d': 0x{d_rec:064x}")
    print(f"[校验] d' 是否等于真实 d ：{d_rec == d_real}")

    # 3) 用恢复的私钥伪造一条“声明”并验签通过（受控演示）
    forged_msg = "This is a controlled fake message"
    k_forge = randint(1, n - 1)
    sig_forge = sm2_sign(d_rec, forged_msg, k_forge)
    ok = sm2_verify(P_real, forged_msg, sig_forge)
    print(f"[伪造签名] r={hex(sig_forge[0])}, s={hex(sig_forge[1])}")
    print(f"[验签通过] {ok}")

if __name__ == "__main__":
    poc_fake_satoshi_signature()