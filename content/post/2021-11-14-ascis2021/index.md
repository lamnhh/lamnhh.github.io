---
title: ASCIS 2021 Finals writeups (WIP)
subtitle: Writeups for crypto and web challenges
date: 2021-11-14
tags: [ascis, ascis2021, ctf, crypto, web]
math: true
---

You can download some of the binaries here: https://drive.google.com/drive/folders/1q9rx2gbuZjSFzXb-_HFdaOV26zPakOAP?usp=sharing

The link contains Crypto01 (buggy), Web02 (chongxun), Jeopardy Crypto01 (noise). My solutions to these challenges are also in there.

## Table of Contents

1. [Crypto](#crypto)

   1.1. [Jeopardy Crypto01 (noise)](#jeopardy-crypto01)

   1.2. [Attack/Defence Crypto01](#attackdefence-crypto01)

2. [Web](#web)

   2.1. [Attack/Defence Web02](#attackdefence-web02)

# Crypto

## Jeopardy Crypto01

```python
from random import randint, getrandbits
from Crypto.Util.number import getPrime  # pycryptodome


class RSA:
    def __init__(self):
        self.e = 65537
        self.p = getPrime(512)
        self.q = getPrime(512)
        self.d = pow(self.e, -1, (self.p - 1) * (self.q - 1))

    def encrypt(self, m: int) -> int:
        return pow(m, self.e, self.p * self.q)

    def noisily_decrypt(self, c: int, d: int = 2021):
        noise = randint(1, d**2-1)
        delta_p = noise % d
        delta_q = noise // d
        return pow(c, self.d, (self.p + delta_p) * (self.q + delta_q))


def main():
    cipher = RSA()

    # what is this?
    print(cipher.encrypt(-1))

    # you need to guess this to get flag
    x = getrandbits(777)
    print(cipher.encrypt(x))

    # will 2021 oracle calls be enough?
    for _ in range(2021):
        guessed_x = int(input())
        if guessed_x == x:
            from secret import FLAG
            print(FLAG)
            return
        else:
            print(cipher.noisily_decrypt(abs(guessed_x)))


if __name__ == '__main__':
    main()
```

First off, it's obvious that $N = \text{cipher.encrypt}(-1) + 1$.

Suppose that we got lucky and got a $noise$ such that $noise \equiv 0 \pmod{d}$, which means $\Delta_p = 0$. Let the noisily-decrypted result be $x'$. Also, suppose that $d$ is odd, if it isn't, create a new session until it is odd.

In this case, we have:

\begin{equation}
\begin{aligned}
(N - 1)^d &\equiv x' \pmod{p(q + \Delta_q)} \\\\
\Leftrightarrow (N - 1)^d + 1 &\equiv x' + 1 \pmod{p(q + \Delta_q)} \\\\
\Leftrightarrow (N - 1)^d + 1 &\equiv x' + 1 \pmod{p} \\\\
\Leftrightarrow (-1)^d + 1 &\equiv x' + 1 \pmod{p} \\\\
\Leftrightarrow 0 &\equiv x' + 1 \pmod{p}
\end{aligned}
\end{equation}

With very high probablity, $GCD(x' + 1, N)$ will be equal to $p$.

Now, how to ensure that $noise \equiv 0 \pmod{d}$? Simple, just connect a few times until it is. $(2020/2021)^{2020} \approx 0.37$, very small.

Solution:

```python
from pwn import process
from Crypto.Util.number import GCD, inverse, isPrime

with process(["python3", "noise.py"]) as tube:
    N = int(tube.recvline().decode()) + 1
    enc_x = int(tube.recvline().decode())

    a = []
    for _ in range(2020):
        tube.sendline(str(N - 1).encode())
        enc = int(tube.recvline().decode())
        a.append(enc)

    for i in range(len(a)):
        g = GCD(a[i] + 1, N)
        if g > 1:
            p = g
            q = N // p
            assert isPrime(p)
            assert isPrime(q)

            phi = (p - 1) * (q - 1)
            e = 65537
            d = inverse(e, phi)
            x = pow(enc_x, d, N)

            tube.sendline(str(x).encode())
            flag = tube.recvline().decode().strip()
            print("Flag: " + flag)
            break
```

## Attack/Defence Crypto01

```python
data = sp.serialize({
    b"issuer": b"vnsecurity",
    b"citizen_id": citizen_id,
    b"citizen_name": citizen_name,
    b"doses": (0).to_bytes(1, "big")
})
```

(`citizen_id` and `citizen_name` is from our input)

The target is to submit a new data with at least 2 `doses`. It's also required to submit a MAC corresponding to the data. There are 5 types of MAC here.

### Aes256XorMP

The MAC is compute by dividing the data into blocks of size 16, encrypting each using AES-256 with the same secret key, then xor-ing all the result together. In case data length is not divisible by 16, pad the data with 0s.

The solution is to use a `citizen_id/citizen_name` such that the last byte (the byte for `doses`) is at the beginning of a new block, and there exists another block in the form of `\2 + \0*15`. It's easy to see that if you swap the two block, the resulting MAC is the same, while `doses` becomes 2.

### Crc32MP

The MAC is compute by taking `CRC32(secret + data)` where `secret` is a random 32-byte pad.

CRC32 has a property that `CRC32(x ^ y ^ z) = CRC32(x) ^ CRC32(y) ^ CRC32(z)` if `x, y, z` are of a same length. (https://en.wikipedia.org/wiki/Cyclic_redundancy_check#Data_integrity). With this, we easy craft new data like this:

Consider `new_data` being `data` with the last byte (for `doses`) replaced with 2, in other words, `new_data = data ^ 0 ^ 2`, then.

`CRC32(secret + new_data) = CRC32(secret + data) ^ CRC32(0) ^ CRC32(2)`.

### DSA

Here is how the signature for a message $m$ is generated:

```python
k = int(time.time())
r = pow(g, k, p) % q
s = pow(k, -1, q) * (m + self.x * r) % q
```

We have the timestamp at the beginning of the session. That timestamp and $k$ should not differ by a lot, which means we can bruteforce $k$.

When we have $k$, generating a signature for $m'$ is obvious:

- $r$ is the same.
- $s' = s + (k^{-1} \mod q) * (m' - m)$

### RSA

We are given everything ($N, e, d$), so we can just compute everything ourselves.

### SHA

The MAC is computed as `SHA256(secret + data)`. It's obvious this is length-extension attack. For Python, this github repo works fine: https://github.com/stephenbradshaw/hlextend. To get the payload in bytes form, wrap the result in a `b""`, then `eval()` it.

# Web

## Attack/Defence Web02

This one is quite straightforward. The one pain that I suffered is to implement curl using `file_get_contents`. Why not just allow `php-curl`? :(

We have:

- A Gitlab instance. This is where the flag is. The flag can only be read using a binary `/readflag`, so the target is to get RCE on this Gitlab instance.
- A PHP website. This is the only thing exposed to us.

The Gitlab version is 13.10.2. I remember reading on Twitter about an RCE on Gitlab recently using some sort of image thingies. A quick search returns this: CVE-2021-22205 (https://pentest-tools.com/blog/detect-gitlab-cve-2021-22205/).

> this security issue affects Gitlab CE versions starting 11.9 and up to 13.10.2

Bingo! Now we need some way to be able to make HTTP requests to the Gitlab instance. Time to look at the PHP site.

First thing first, the site check authentication just by taking the `user` cookie, strip the last 32 bytes, use the rest as username to search in database. If that username exists, we are authenticated. So the solution is to put `'chongxun' + 'a' * 32` in that cookie.

The next thing noticable is the `/upload.php` route. This route allows us to upload any file that is not `.php`, `.pht`, or `.phar`. The extension check is very thorough, there is no chance to bypass it to upload a `.php` file. However, it turns out that there is another extension that can perform the same as `.php`: `.phtml`. We can now upload a shell to the PHP instance.

I then wasted half an hour trying to get RCE using the uploaded shell, only to realize that `system, exec, etc` are disabled in `php.ini`. This means we need to do everything using pure, painful PHP. Also, `php-curl` is not installed, but we can use `file_get_contents` instead.

The rest is just 4 hours of pain simulating the process of signing up, signing in, attaching file to new snippet, etc, using `file_get_contents`.

There are a few things I was able to learned from this:

- PHP is fucking stupid.
- PHP is evil.

For real, why is `'\n'` escaped but `"\n"` isn't?. And why is the syntax for POST-ing with `file_get_contents` so complicated? Why does it not take an array as headers? I had to pull up Wireshark to debug this fucking thing.

Also, why is `file_get_contents` able to POST to begin with?.

Okay, there is still the Java chal and one more crypto chal left. The crypto challenge feels very impossible, and Java just scares me in general.

Finally, F to my uni's team. You did well.
