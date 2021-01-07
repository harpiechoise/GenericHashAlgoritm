from random import seed, randint
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

H_copy = H[:]

LOOKUP = [i for i in range(ord('a'), ord('z'))] + \
    [i for i in range(ord('A'),  ord('Z'))]


def SHR(x, n):
    return (x & MASK) >> n


def ROTR(x, y):
    return (((x & 0xffffffff) >> (y & 31)) | (x << (32 - (y & 31)))) & 0xffffffff


def CH(x, y, z):
    return (x & y) ^ (~x ^ z)


def MAJ(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)


def sigma0(x):
    return ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22)


def sigma1(x):
    return ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25)


def gamma0(x):
    return ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3)


def gamma1(x):
    return ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10)


def fill_message(message: str) -> str:
    # Convert string to 8 bits binary
    res = "".join([format(ord(i), '08b') for i in message])
    l = len(res)
    # Add the extra bit in the end
    res += "1"
    # Add zeros with the formula x = (448 - l - 1) mod 512
    zeros = (448 - l - 1) % 512
    res += "0"*zeros
    # Encode the lenght of the message in 64bits format
    encoded_len = "{0:064b}".format(l)
    res += encoded_len
    return res


def chunk_message(l: list, n: int):
    for i in range(0, len(l), n):
        yield l[i:i+n]


def leading_zeros(n: int) -> list:
    return "0"*n


def mod_32_sum(a: int, b: int) -> int:
    # Mod 32 sum
    r = (a + b) % 2**32
    # Padding to 32 bits
    b = f"{r:032b}"
    return int(b, 2)


def main_loop(encoded_message: str):
    # Get the first chunk of the message split into 512bits parts
    chunks = list(chunk_message(encoded_message, 512))
    # Register inicialization
    a, b, c, d, e, f, g, h = H_copy
    # For each one of the pieces of the hashes
    for chunk in chunks:
        # Create 64 words empty array
        w = []
        for i in range(0, 64):
            w.append(int(leading_zeros(32), 2))
        # Split the first section of 512 bits of the message un 16 pieces of 32 bits
        message_bits = list(chunk_message(chunk, 32))
        for idx, _ in enumerate(message_bits):
            w[idx] = int(message_bits[idx], 2)

        # We apply the correspondent operation to calculate the missing words
        for i in range(16, 64):
            w[i] = mod_32_sum(mod_32_sum(mod_32_sum(
                gamma1(w[i-2]), w[i-7]), gamma0(w[i-15])), w[i-16])

        for i in range(64):
            # Calculate the Temp 1 and Temp 2 register
            # h + Σ1(e) + Ch(e, f, g) + k_1 + w_i
            T1 = mod_32_sum(mod_32_sum(mod_32_sum(mod_32_sum(
                h, sigma1(e)), CH(e, f, g)), CONST_SHA256[i]), w[i])
            # Σ0(a) + Maj(a, b, c)
            T2 = mod_32_sum(sigma0(a), MAJ(a, b, c))

            # Update the registers
            h = g       # h -> g -> f -> e -< d + T1 -> c -> b -> a - T1 + T2
            g = f
            f = e
            e = mod_32_sum(d, T1)
            d = c
            c = b
            b = a
            a = mod_32_sum(T1, T2)

        register_list = [a, b, c, d, e, f, g, h]
        # Mod sum into the 7 register to update the final hash
        for idx, _ in enumerate(H):
            H_copy[idx] = mod_32_sum(register_list[idx], H[idx])

    return H_copy


def modify_hash_words(message: str):
    # Get the message preprocessed
    message_encoded = fill_message(message)
    # Encode the message with the main SHA256 modified loop
    final_H = main_loop(message_encoded)
    # Copy the final hashes list
    seeds = final_H[:]
    # Make a dictionary for store the letters
    letters = []
    for s in seeds:
        # Take the hash list coreword as seed
        seed(s)
        # Generate a random number between 0 and a Prime Number
        index = randint(0, 0x13D573) % 50
        # And append the letter in the lookup table to the letters array
        letters.append(chr(LOOKUP[index]).upper())
    # Now we calculate the hashes
    hashes = []
    for idx, letter in enumerate(letters):
        # We encode the message and take a coreword for every hash generated
        hashes.append(main_loop(fill_message(letter))[idx])
    for idx, hash_ in enumerate(hashes):
        # We sum the random factor to the final hash
        final_H[idx] = mod_32_sum(hash_, final_H[idx])

    for idx, hash_ in enumerate(final_H):
        # We take a constant for every hash number
        final_H[idx] = mod_32_sum(CONST_SHA256[hash_ % 64], final_H[idx])
    return final_H


def hexdigest(message: str) -> int:
    # Now we take the final hash
    final_H = modify_hash_words(message)
    # We encode the final hash to binary
    final_H_bin = "".join([f"{i:032b}" for i in final_H])
    # And encode the final ash to int
    final_h_bin_to_int = int(final_H_bin, 2)
    # And return like HEX
    return hex(final_h_bin_to_int).replace("0x", "")
