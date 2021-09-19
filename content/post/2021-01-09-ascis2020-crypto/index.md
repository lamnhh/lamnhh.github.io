---
title: ASCIS 2020 - Crypto writeups
subtitle: Writeups for Crypto01 daemon
date: 2021-01-09
tags: [ascis, ascis2020, ctf, crypto]
math: true
---

This is me upsolving the challenges 1 month after the contest. All patches are unavailable to download, so all I discuss here is how to attack the original challenges (with no patches).

The challenge can be summarised as:

- Given an oracle $E$ which we can query: give it a string $s$ and it will return $E(s)$.
- The target is to forge $E(target)$ where

$$target = \text{0x2020202020202020202020202020202020202020202020202020202020202020}$$

(32 bytes 0x20). The catch is that we cannot query for $E(target)$ directly.

There are 3 oracles we need to attack:

- AES-CBC 256
- AES-GCM 256
- RSA on Gaussian integers

# AES-CBC 256

![CBC Encryption](https://upload.wikimedia.org/wikipedia/commons/thumb/8/80/CBC_encryption.svg/1920px-CBC_encryption.svg.png "CBC Encryption")

The oracle randomises its IV, requires the plaintext to be exactly 32 bytes long (2 blocks), which means it will feed into the cipher 3 blocks of data (because of padding). We have the exact flowchart as the image above.

The solution is:

- First, query $E(00 * 16 + 20 * 16)$, we get back $IV$ and $CT$.
- Second, compute $IV' = IV \oplus (20 * 16)$.
- Submit $IV' + CT$ and get the flag.

Explanation: call the first block of plaintext $PT$. For our plaintext, we have $PT = 00 * 16$.

We can see that:

$PT \oplus IV = (PT \oplus (20 * 16)) \oplus (IV \oplus (20 * 16)) = (target PT) \oplus IV'$

What this means is that using target PT and IV', we have the same first block of ciphertext as above. The rest blocks will subsequently be the same. Now we have the full ciphertext for $target$.

# AES-GCM 256

![GCM encryption](https://upload.wikimedia.org/wikipedia/commons/thumb/2/25/GCM-Galois_Counter_Mode_with_IV.svg/800px-GCM-Galois_Counter_Mode_with_IV.svg.png "GCM encryption")

GCM summarised: first encrypt the plaintext using CTR mode, then use ciphertext blocks as coefficients for a polynomial, compute it on a key-dependent point H, encrypt it, then return as an authentication tag.

This challenge is quite different from the other two. First, we look at the secret key initialisation:

```python
with open("/opt/flag/secret", "rb") as f:
    tp = Aes256GcmTP(f.read())
```

This means the secret key is the same over all connections.

Second, nonce initialisation:

```python
# this is the best way to avoid nonce reuse
now = int(time())
if now <= self.last_timestamp:
    now = self.last_timestamp + 1
self.last_timestamp = now
nonce = now.to_bytes(12, "big")
```

This obviously can be bypassed using race condition.

Now we have an GCM oracle that uses same secret key and same nonce for all queries. That means the encryption is a stream cipher with same key $\Rightarrow$ we can forge ciphertext however we like.

To forge the authentication tag, we need to look more closely at the math. The tag is computed as follow:

- Compute $H = E(0^{128})$.
- Compute $pad = E(nonce \| 0^{31} \| 1)$.
- Call $c_1, c_2$ the two blocks of the ciphertext.
- The tag is: $c_1 \cdot H^3 + c_2 \cdot H^2 + (len(A) \| len(C)) \cdot H + pad$

Here we have $len(A) = 0, len(C) = 32 * 8 = 256$. All computation is on $GF(2^{128})$. This is a field, which means it has distributivity, a.k.a. $A(B+C) = AB + AC$. That means, consider 3 same-length ciphertext $c^1, c^2, c^3$, we have:

$tag(c^1) + tag(c^2) + tag(c^3)$
$= (c^1_1 + c^2_1 + c^3_1) \cdot H^3 + (c^1_2 + c^2_2 + c^3_2) \cdot H_2 + (len(A) \| len(C)) \cdot H + pad$
$= tag(c^1 + c^2 + c^3) $

_(reminder that addition in $GF(2^n)$ is the XOR operation)_

Define $et = E(target)$ (ciphertext for $target$). If we can forge these 3 values:

- `c1 = et[:16] + 00 * 16`
- `c2 = 00 * 16 + et[16:]`
- `c3 = 00 * 32`

then we have $tag(c^1) + tag(c^2) + tag(c^3) = tag(c^1 + c^2 + c^3) = tag(E(target))$

To construct $c^1, c^2, c^3$ we do as follow:

- Define $p = random(32 bytes)$
- Query $E(p)$.
- Compute $E(target) = E(p) \oplus p \oplus target$.
- Compute $p^1 = target \oplus (E(target)[:16] \| (00 * 16))$
- Compute $p^2 = target \oplus ((00 * 16) \| E(target)[16:])$
- Compute $p^3 = target \oplus E(target)$

Then it's easy to see that $E(p^i) = c^i$.

# RSA with Gaussian integers

The string we submit is split into 2 halves, each converted to an integer, combined together into a Complex number. This complex number is then RSA-ed, concatenated, and returned to us.

We do not know $N$ and $e$.

The multiplication function is this:

```python
def complex_mult(c1, c2, modulus):
    return Complex(
        (c1.re * c2.re - c1.im * c2.im) % modulus,  # real part
        (c1.re * c2.im + c1.im * c2.re) % modulus,  # image part
    )
```

We define $norm(a) = a.re^2 + a.im^2$.

It's easy to see that $norm$ is multiplicative. In other word: $norm(c1 \cdot c2) = norm(c1) \cdot norm(c2)$. This means that we have:

$norm(s)^e \equiv norm(s^e) \equiv norm(E(s))\ (mod\ N)$

which is regular RSA.

To find $N$, we query 3 values: $E(2), E(4), E(8)$. We can see that:

\begin{equation}
    \begin{aligned}
        E(2) \cdot E(2)
        &\equiv 2^e \cdot 2^e \\\\
        &\equiv 4^e \\\\
        &\equiv E(4) \pmod N \\\\
        \Leftrightarrow E(2)^2 - E(4) &\equiv 0\ \pmod N \\\\
        \\\\
        E(2) \cdot E(2) \cdot E(2)
        &\equiv 2^e \cdot 2^e \cdot 2^e \\\\
        &\equiv 8^e \\\\
        &\equiv E(8) \pmod N \\\\
        \Leftrightarrow E(2)^3 - E(8) &\equiv 0 \pmod N
    \end{aligned}
\end{equation}

From that, we have:

$$N \mid GCD(E(2)^2 - E(4), E(2)^3 - E(8))$$

Define $g = GCD(E(2)^2 - E(4), E(2)^3 - E(8))$. By experiment, we can see that most prime factors of $g$ (except for $p, q$) is small (no greater than 1000). We now have $N$. Then I spent the next 12 hours struggling to compute $e$, only to realise that I don't need it :(

It's easy to see that:

\begin{equation}
    \begin{aligned}
        E(2target) &\equiv E(2) \cdot E(target)  \pmod N \\\\
        \Leftrightarrow E(target) &\equiv E(2target) \cdot E(2)^{-1} \pmod N
    \end{aligned}
\end{equation}

$E(2)^{-1}\ mod\ N$ can be easily computed using extended Euclid alg (we already have $E(2)$ and $N$).

Done.

<style>
    .medium-zoom-image {
       background-color: #fff;
    }
</style>
