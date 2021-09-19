---
title: Recover public keys from JWTs signed using RS256
date: 2021-02-22
math: true
tags: [ctf, crypto]
---

# Scenario

A web server uses RS256 algorithm for their JWT signing. Both public key and private key are unknown. The adversary can query the server to sign a chosen message. The goal is to recover the public key.

# How JWT works

Take a look at a sample JWT:

```
eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJicm9uemUiLCJmZnAiOiJDQTEyMzQxMjM0In0.jv953fHSWqvR7SY8l3g2ku_BRAXqIvKOIq_lAjPXWXgUeIml6myJeRmqoSkDZ3-YpyyQ2hQxTuBip8igyhOHz0dc6A08Psip1KuqVjnilywN1JcH0euXGVQeeI-FwdeIArPwfoDUFXXKz8sh3EO9gK6dAwmWGLAV4wMF50fVjb7WuHEiL6w9WOeKfBneV4_3skDm8ljXoGGGyP7YkL6ez-fwacIe7_m-4MuQdfZfO1t-g2Vjr-yaImUHrZyW9Q8cAM3eJZ7m0UCnb8pG5yd8rU5vcXovKrbX6ZIYwaw4-IvFtJdU6h2jXwm2uKjRnhfYezi_iKARFO2Mv3vJmkX-Kg
```

It consists of 3 parts:

Header:

```
eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9
```

Payload:

```
eyJzdGF0dXMiOiJicm9uemUiLCJmZnAiOiJDQTEyMzQxMjM0In0
```

Signature:

```
jv953fHSWqvR7SY8l3g2ku_BRAXqIvKOIq_lAjPXWXgUeIml6myJeRmqoSkDZ3-YpyyQ2hQxTuBip8igyhOHz0dc6A08Psip1KuqVjnilywN1JcH0euXGVQeeI-FwdeIArPwfoDUFXXKz8sh3EO9gK6dAwmWGLAV4wMF50fVjb7WuHEiL6w9WOeKfBneV4_3skDm8ljXoGGGyP7YkL6ez-fwacIe7_m-4MuQdfZfO1t-g2Vjr-yaImUHrZyW9Q8cAM3eJZ7m0UCnb8pG5yd8rU5vcXovKrbX6ZIYwaw4-IvFtJdU6h2jXwm2uKjRnhfYezi_iKARFO2Mv3vJmkX-Kg
```

Each of these part is base64-ed. The signature is computed on `Header + "." + Payload`. The signing algorithm is specified in the raw header (in the sample above, it's RS256 - RSA with SHA256).

# How RS256 works

RS256 - RSA with SHA256 does the following:

- Encode the message using EMSA-PKCS1-v1_5 ([RFC3447, section9.2](https://tools.ietf.org/html/rfc3447#section-9.2)) with SHA256 as the hash function
- Perform textbook RSA signing on the encoded message

## More detail on the RSA part

Given the key $(N, e, d)$, the signature for message $m$ is computed as:

$$s = m^d \pmod{N}$$

To verify the signature, check if:

$$
\begin{equation}
    s^e \equiv m^{de} \equiv m \pmod{N}
    \label{eq:sample}
    \tag{*}
\end{equation}
$$

# The attack

From $(*)$, we can see that:

$$s^e - m \equiv 0 \pmod{N}$$

Given a lot of $(message, signature)$ pairs $(m_1, s_1), (m_2, s_2), ..., (m_k, s_k)$, with high chance, we will get $N$ when we compute:

$$GCD(s_1^e - m_1, s_2^e - m_2, ..., s_k^e - m_k)$$

## **_Where does e come from?_**

$e$ is usually in the form $2^{2^k} + 1$ with small $k$. We can bruteforce $e$.

## **_When can this attack be fatal?_**

When the server uses a JWT library that is vulnerable to key confusion (can use RSA key to decode HS256 tokens), for example, CVE-2016-10555 or CVE-2017-11424.

In those cases, the attacker can modify the `alg` field to HS256 in the header, change the payload however they want, then sign it with the public key with HS256 algorithm. The server will decode the token using the public key, thus giving the attacker authentication.

## **_Notes about implementation_**

JWT keys are usually large (at least 2048 bit long). Computing $s^e$ can be very slow. For Python, use `mpz` from `gmpy2` to speed up things.

Sample implementation (writeup for the Cr0wnAir challenge (the crypto part) from [UnionCTF 2021](https://ctftime.org/event/1246)):

```python
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Util.number import bytes_to_long, long_to_bytes
from base64 import b64decode, urlsafe_b64decode
from gmpy2 import gcd, mpz


target_bit_length = 2048
jwt_list = [
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJicm9uemUiLCJmZnAiOiJDQTEyMzQxMjM0In0.jv953fHSWqvR7SY8l3g2ku_BRAXqIvKOIq_lAjPXWXgUeIml6myJeRmqoSkDZ3-YpyyQ2hQxTuBip8igyhOHz0dc6A08Psip1KuqVjnilywN1JcH0euXGVQeeI-FwdeIArPwfoDUFXXKz8sh3EO9gK6dAwmWGLAV4wMF50fVjb7WuHEiL6w9WOeKfBneV4_3skDm8ljXoGGGyP7YkL6ez-fwacIe7_m-4MuQdfZfO1t-g2Vjr-yaImUHrZyW9Q8cAM3eJZ7m0UCnb8pG5yd8rU5vcXovKrbX6ZIYwaw4-IvFtJdU6h2jXwm2uKjRnhfYezi_iKARFO2Mv3vJmkX-Kg",
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJicm9uemUiLCJmZnAiOiJDQTEyMzQxMjM1In0.vtp96NW_PxO-_GW2e1u0xu4FTMYjYgwfe2wYKuksUGE_lM1ZeiyitDiUMXaQ3s5T3pD9ALHcqpsBY-5z1DbxVgPMvrqaExnw0merTDm17ku3b0ys5-dJOybb0meI7eu4i-Qykh0X_XHyOlxT6H-ZyxCcKov9sbnJVk3fbZY2lzjKuYZAIYQzXd5J65GooA7vkR2cWeK6rypHFyDPtuFaPLOhE6cLbC9VVyD4oxu0bvkpW6lRuiQni-S4uMkH2y7OUA16nNNVVwixUGVPwzGW8oS61lXiA3OHp1o336cyKJ9B4_ae1FeClPgUAnH_CWQIoZzco2Jb3mnHFq7lVgBnug",
]


def b64urldecode(b64: str) -> str:
    return urlsafe_b64decode(b64+("=" * (len(b64) % 4)))


def parse(jwt: str) -> (bytes, bytes):
    tokens = jwt.split(".")
    return ".".join(tokens[0:2]), b64urldecode(tokens[2])


def get_rsa_mc(jwt: str) -> int:
    inp, sig = parse(jwt)
    h = SHA256.new(inp.encode())
    m = bytes_to_long(
        PKCS1_v1_5.pkcs1_15._EMSA_PKCS1_V1_5_ENCODE(h, target_bit_length // 8)
    )
    c = bytes_to_long(sig)
    return mpz(m), mpz(c)


def get_pubkey(n: int, e: int) -> str:
    k = RSA.construct([n, e])
    return k.export_key("PEM")


ms = []
cs = []
for jwt in jwt_list:
    m, c = get_rsa_mc(jwt)
    ms.append(m)
    cs.append(c)

assert len(ms) > 0 and len(cs) == len(ms)

e = 65537
n = pow(cs[0], e) - ms[0]
for i in range(1, len(ms)):
    m = ms[i]
    c = cs[i]
    n = gcd(n, pow(c, e) - m)

for i in range(2, 1000):
    while n % i == 0:
        n //= i
n = int(n)

print(n)
print(get_pubkey(n, e))
```

## **_Lessons_**

- Do not rely on public keys for security purposes.
- Be careful when using JWT. Or even better, don't use them.

# References

- [Abusing JWT public keys without the public key](https://blog.silentsignal.eu/2021/02/08/abusing-jwt-public-keys-without-the-public-key/)
