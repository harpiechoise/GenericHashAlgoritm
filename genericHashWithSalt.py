"""
Implementación del Secure Hash Algorithm en Python, fuentes externas
https://csrc.nist.gov/csrc/media/publications/fips/180/4/final/documents/fips180-4-draft-aug2014.pdf

https://www.youtube.com/watch?v=f9EbD6iY9zI&ab_channel=learnmeabitcoin
"""
# Los words son un grupo de 32 bits (4 bytes) o 64 bits (8 bytes) dependiendo del algoritmo de secure hash que se este usando
WORD_SIZE = 32
# El tamaño de cada bloque que se genera y se vuelve a iterar con el algoritmo de computación
BLOCK_SIZE = 64
# El tamaño del DIGEST
MESSAGE_DIGEST_SIZE = 32
# (w - n) seccion 3. Notaciones y Convenciones
W_MINUS_N = 32
# Mascara 3. Notaciones u convenciones
MASK = 0xffffffff

# Constantes 4. Funciones y constantes
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

# 5.3.3 SHA-256
H = [
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19
]


def SHR(x, n):
    # La operacion de Shift right logica paddeando los bits
    # x >> n
    return (x & MASK) >> n


def ROTR(x, y):
    # La operacion Rotate Left rota los bits hacia la izquieda indefinidamente
    # (w >> n) ∨ (x << w - n)
    left = ((x & MASK) >> (y & W_MINUS_N - 1))
    right = (x << W_MINUS_N - (y & W_MINUS_N - 1)) & MASK
    return right | left


def CH(x, y, z):
    # La operacion Choice que escoge el bit mas significavo
    # (x ∧ y) ⊕ (¬ x ∧ z)
    return z ^ (x & (y ^ z))


def MAJ(x, y, z):
    # Escoge el bit mas frecuente entre x, y, z
    # (x ∧ y) ⊕ (x ∧ z) ⊕ (y ∧ z)
    return ((x | y) & z) | (x & y)


def sigma0(x):
    # ROTR2 (x) ⊕ ROTR13 (x) ⊕ ROTR22(x)
    return ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22)


def sigma1(x):
    # ROTR6 (x) ⊕ ROTR11 (x) ⊕ ROTR25(x)
    return ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25)


def gamma0(x):
    # ROTR7 (x) ⊕ ROTR18 (x) ⊕ SHR3 (x)
    return ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3)


def gamma1(x):
    # ROTR17 (x) ⊕ ROTR19 (x) ⊕ SHR10 (x)
    return ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10)


def computation(data, initial_hash):
    # La copia de la lista H
    initial_hash_copy = initial_hash.copy()
    # Inicializa W
    # Se prepara la tarea para el mensaje W_t
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

    # Comienza la computación
    for idx in range(0, -64, -1):
        i = abs(idx % 8)
        # Se calculan las posiciones que se tienen que tomar en el vector H
        positions = [(i + x) % 8 for x in range(8)]
        # Posicion D
        d_position = positions[3]
        # Posicion H
        h_position = positions[-1]
        # Se calculan los valores de a .. h
        a, b, c, d, e, f, g, h = [initial_hash_copy[pos] for pos in positions]
        # Se calcula t_1
        t1 = h + sigma1(e) + CH(e, f, g) + \
            CONST_SHA256[abs(idx)] + w[abs(idx)]
        # Se calcula t_2
        t2 = sigma0(a) + MAJ(a, b, c)
        # Se toman las posicion d y h y se reemplaza por las respectivas variables enmascaradas
        initial_hash_copy[d_position] = (d + t1) & MASK
        initial_hash_copy[h_position] = (t1 + t2) & MASK

    return [(x + initial_hash_copy[idx]) & MASK for idx, x in enumerate(initial_hash)]


def leading_zeros(count):
    # Paddear Valores con Ceros
    return [0] * count


class MyHASH:
    def __init__(self, string=None):
        # Se prepara la instancia del algoritmo
        self._sha = {
            'digest': H,
            'count_lo': 0,
            'count_hi': 0,
            'data': leading_zeros(BLOCK_SIZE)
        }
        # Se define un Byte Buffer
        buff = None
        # se comprueba de que haya un valor inical
        if not string:
            raise ValueError(f"Initial data expected but got {string}")
        # Se convierte el valor buffer
        if isinstance(string, str):
            buff = memoryview(bytearray(string, 'utf8'))
        else:
            raise TypeError(f"Expecting string type but got {type(string)}")

        # Se toma el largo del buffer
        count = len(buff)
        # Y se calcula cuenta minima
        count_lo = (self._sha['count_lo'] + (count << 3)) & MASK
        # Si estas menor a 0
        if count_lo < self._sha['count_lo']:
            # Se asigna a 1
            self._sha['count_hi'] += 1
        # De otro modo se asigna la cuenta a la variable
        self._sha['count_lo'] = count_lo
        # Se asigna la cuenta alta a la cuenta con 29 bits a la derecha
        self._sha['count_hi'] += (count >> 29)
        # Se inicializa el indice del buffer
        buffer_idx = 0
        # Comienza la computacion por bloques
        while count >= BLOCK_SIZE:
            self._sha['data'] = [
                c for c in buff[buffer_idx:buffer_idx + BLOCK_SIZE]]
            count -= BLOCK_SIZE
            buffer_idx += BLOCK_SIZE
            self._sha['digest'] = computation(
                self._sha['data'], self._sha['digest'])
        # Se reestablecen los datos al buffer original
        self._sha['data'][:count] = [
            c for c in buff[buffer_idx:buffer_idx + count]]

    def hexidigest(self):
        # Se copia los valores de la instancia actual
        hash_ = self._sha.copy()
        count = (hash_['count_lo'] >> 3) & 0x03f
        hash_['data'][count] = 0x80
        count += 1

        # Si la cuenta es mayor al blocksize actual - 8
        if count > BLOCK_SIZE - 8:
            # Se corta la cadena de datos
            hash_['data'] = hash_['data'][:count] + \
                leading_zeros(BLOCK_SIZE - count)
            # Se computa el digest previo
            hash_['digest'] = computation(hash_['data'], hash_['digest'])
            # Se paddea con ceros
            hash_['data'] = [0] * BLOCK_SIZE
        else:
            # Si no simplemente se paddea con ceros
            hash_['data'] = hash_['data'][:count] + \
                leading_zeros(BLOCK_SIZE - count)

        # Se hacen los bit shift para aleatoreizar la cadena
        for idx, shift in zip(range(56, 64), list(range(24, -1, -8)) * 2):
            hash_['data'][idx] = (
                hash_['count_hi' if idx < 60 else 'count_lo'] >> shift) & 0xff

        # Se computa el digest final
        hash_['digest'] = computation(hash_['data'], hash_['digest'])

        # Se convierte a una cadena de texto en hexadecimal aplicando los ultimos shitfs
        digest = []
        for i in hash_['digest']:
            for shift in range(24, -1, -8):
                digest.append((i >> shift) & 0xff)
        return "".join(["%.2x" % i for i in digest[:MESSAGE_DIGEST_SIZE]])


class SaltAlgorithm():
    # Trata de aleatorizar la cadena resultante n veces
    def __init__(self, inital_value="16", how_much=100):
        self.value = inital_value
        self.salt = how_much

    def get_salted_value(self):
        value = self.value
        for _ in range(self.salt):
            value = MyHASH(value).hexidigest()
        return value


if __name__ == "__main__":
    contraseña = "1"
    print(MyHASH(contraseña).hexidigest())
