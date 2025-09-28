from secrets import randbelow
from py_ecc.optimized_bls12_381 import curve_order as r
from py_ecc.bls import G2Basic as bls

sk_int = randbelow(r - 1) + 1        # 1 .. r-1
pk_bytes = bls.SkToPk(sk_int)        # 48-byte compressed G1 public key
print(pk_bytes.hex())
pk_bytes = bls.SkToPk(sk_int)

print("Secret key (mod r):", hex(sk_int))
print("Public key (48-byte compressed G1):", pk_bytes.hex())