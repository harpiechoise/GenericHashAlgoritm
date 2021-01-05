"""
Implementación del Secure Hash Algorithm en Python, fuentes externas
https://csrc.nist.gov/csrc/media/publications/fips/180/4/final/documents/fips180-4-draft-aug2014.pdf

https://www.youtube.com/watch?v=f9EbD6iY9zI&ab_channel=learnmeabitcoin
"""
# Los words son un grupo de 32 bits (4 bytes) o 64 bits (8 bytes) dependiendo del algoritmo de secure hash que se este usando
WORD_SIZE = 32
BLOCK_SIZE = 64
MESSAGE_DIGEST_SIZE = 32
W_MINUS_N = 32
MASK = 0xffffffff

CONST_SHA256 = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

H = [
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19
]


def SHR(x, n):
    return (x & MASK) >> n


def ROTR(x, y):
    left = ((x & MASK) >> (y & W_MINUS_N - 1))
    right = (x << W_MINUS_N - (y & W_MINUS_N - 1)) & MASK
    return right | left


def CH(x, y, z):
    return z ^ (x & (y ^ z))


def MAJ(x, y, z):
    return ((x | y) & z) | (x & y)


def sigma0(x):
    return ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22)


def sigma1(x):
    return ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25)


def gamma0(x):
    return ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3)


def gamma1(x):
    return ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10)


def encode_message(message: str):
    return [ord(x) for x in message]


def computation(data, initial_hash):
    initial_hash_copy = initial_hash.copy()
    w = []
    for i in range(0, 16):
        w.append(sum([
            data[4 * i + 0] << 24,
            data[4 * i + 1] << 16,
            data[4 * i + 2] << 8,
            data[4 * i + 3] << 0,
        ]))

    for i in range(16, 64):
        gamma_sum = gamma1(w[i - 2] + w[i - 7] + gamma0(w[i - 15]) + w[i - 16])
        w.append(gamma_sum & MASK)

    for idx in range(0, -64, -1):
        i = abs(idx % 8)
        positions = [(i + x) % 8 for x in range(8)]
        d_position = positions[3]
        h_position = positions[-1]
        a, b, c, d, e, f, g, h = [initial_hash_copy[pos] for pos in positions]

        t1 = h + sigma1(e) + CH(e, f, g) + \
            CONST_SHA256[abs(idx)] + w[abs(idx)]
        t2 = sigma0(a) + MAJ(a, b, c)
        initial_hash_copy[d_position] = (d + t1) & MASK
        initial_hash_copy[h_position] = (t1 + t2) & MASK

    return [(x + initial_hash_copy[idx]) & MASK for idx, x in enumerate(initial_hash)]


def leading_zeros(count):
    return [0] * count


class MyHASH:
    def __init__(self, string=None):
        self._sha = {
            'digest': H,
            'count_lo': 0,
            'count_hi': 0,
            'data': leading_zeros(BLOCK_SIZE)
        }

        buff = None
        if not string:
            raise ValueError(f"Initial data expected but got {string}")

        if isinstance(string, str):
            buff = memoryview(bytearray(string, 'utf8'))
        else:
            raise TypeError(f"Expecting string type but got {type(string)}")

        count = len(buff)
        count_lo = (self._sha['count_lo'] + (count << 3)) & MASK

        if count_lo < self._sha['count_lo']:
            self._sha['count_hi'] += 1
        self._sha['count_lo'] = count_lo
        self._sha['count_hi'] += (count >> 29)

        buffer_idx = 0

        while count >= BLOCK_SIZE:
            self._sha['data'] = [
                c for c in buff[buffer_idx:buffer_idx + BLOCK_SIZE]]
            count -= BLOCK_SIZE
            buffer_idx += BLOCK_SIZE
            self._sha['digest'] = computation(
                self._sha['data'], self._sha['digest'])

        self._sha['data'][:count] = [
            c for c in buff[buffer_idx:buffer_idx + count]]

    def hexidigest(self):
        hash_ = self._sha.copy()
        count = (hash_['count_lo'] >> 3) & 0x03f
        hash_['data'][count] = 0x80
        count += 1

        if count > BLOCK_SIZE - 8:
            hash_['data'] = hash_['data'][:count] + \
                leading_zeros(BLOCK_SIZE - count)
            hash_['digest'] = computation(hash_['data'], hash_['digest'])
            hash_['data'] = [0] * BLOCK_SIZE
        else:
            hash_['data'] = hash_['data'][:count] + \
                leading_zeros(BLOCK_SIZE - count)

        for idx, shift in zip(range(56, 64), list(range(24, -1, -8)) * 2):
            hash_['data'][idx] = (
                hash_['count_hi' if idx < 60 else 'count_lo'] >> shift) & 0xff

        hash_['digest'] = computation(hash_['data'], hash_['digest'])

        digest = []
        for i in hash_['digest']:
            for shift in range(24, -1, -8):
                digest.append((i >> shift) & 0xff)
        return "".join(["%.2x" % i for i in digest[:MESSAGE_DIGEST_SIZE]])


class SaltAlgorithm():
    def __init__(self, inital_value="Something", how_much=100):
        self.value = inital_value
        self.salt = how_much

    def get_salted_value(self):
        value = self.value
        for i in range(self.salt):
            value = MyHASH(value).hexidigest()
        return value


if __name__ == "__main__":
    myhash = SaltAlgorithm()
    a = myhash.get_salted_value()
    print(a)
