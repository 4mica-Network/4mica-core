from secrets import randbelow
from py_ecc.optimized_bls12_381 import curve_order as r
from py_ecc.bls import G2Basic as bls

sk_int = 0x6f3eff11070f29192c5f2dde4d047f99fc7861fd82593d22859d5ca03d9e476b       # 1 .. r-1
pk_bytes = bls.SkToPk(sk_int)        # 48-byte compressed G1 public key
print(pk_bytes.hex())
pk_bytes = bls.SkToPk(sk_int)

print("Secret key (mod r):", hex(sk_int))
print("Public key (48-byte compressed G1):", pk_bytes.hex())