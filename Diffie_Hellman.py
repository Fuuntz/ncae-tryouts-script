import secrets
import hashlib
#Something is wrong with my diffie hellman implementation here... Can you spot it?
p = int("""
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1
29024E088A67CC74020BBEA63B139B22514A08798E3404DD
EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245
E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED
EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381
FFFFFFFFFFFFFFFF
""".replace("\n", ""), 16)
g = p - 1  

a = secrets.randbelow(p)
b = secrets.randbelow(p)

A = pow(g, a, p)
B = pow(g, b, p)


s = pow(B, a, p)


def keystream(secret, length):
    out = b""
    counter = 0
    while len(out) < length:
        data = f"{secret}:{counter}".encode()
        out += hashlib.sha256(data).digest()
        counter += 1
    return out[:length]

ciphertext = bytes.fromhex(
    "73673c2a9a27d4cd7578677fc06d4f5e9084042515c2903612c4c3d472224b80923e"
)

print("p =", p)
print("g =", g)
print("A =", A)
print("B =", B)
print("ciphertext =", ciphertext.hex())
