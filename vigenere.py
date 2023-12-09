import sys

MAX_KEY_LENGTH_GUESS = 20
alphabet = 'abcdefghijklmnopqrstuvwxyz'

# Frequency of each letter in the English language
english_frequencies = [0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015,
                      0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749,
                      0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758,
                      0.00978, 0.02360, 0.00150, 0.01974, 0.00074]


# Computing the index of coincidence
def get_index_coincidence(ciphertext):
    N = float(len(ciphertext))
    frequency_sum = 0.0
    for letter in alphabet:
        frequency_sum += ciphertext.count(letter) * (ciphertext.count(letter) - 1)
    ic = frequency_sum / (N * (N - 1))
    return ic


# Compute the most likely period of the key using the index of coincidence
def get_key_length(ciphertext):
    ic_table = []
    for guess_len in range(MAX_KEY_LENGTH_GUESS):
        ic_sum = 0.0
        avg_ic = 0.0
        for i in range(guess_len):
            sequence = ""

            for j in range(0, len(ciphertext[i:]), guess_len):
                sequence += ciphertext[i + j]
            ic_sum += get_index_coincidence(sequence)

        if not guess_len == 0:
            avg_ic = ic_sum / guess_len
        ic_table.append(avg_ic)

    best_guess = ic_table.index(sorted(ic_table, reverse=True)[0])
    second_best_guess = ic_table.index(sorted(ic_table, reverse=True)[1])

    # Since this program can sometimes think that a key is literally twice itself, or three times itself
    if best_guess % second_best_guess == 0:
        return second_best_guess
    else:
        return best_guess


# Performs frequency analysis on the "sequence" of the ciphertext
def frequency_analysis(sequence):
    all_chi_squareds = [0] * 26
    for i in range(26):
        chi_squared_sum = 0.0
        sequence_offset = [chr(((ord(sequence[j]) - 97 - i) % 26) + 97) for j in range(len(sequence))]
        v = [0] * 26

        for l in sequence_offset:
            v[ord(l) - ord('a')] += 1

        for j in range(26):
            v[j] *= (1.0 / float(len(sequence)))

        # compare to the english frequencies
        for j in range(26):
            chi_squared_sum += ((v[j] - float(english_frequencies[j])) ** 2) / float(english_frequencies[j])

        all_chi_squareds[i] = chi_squared_sum

    shift = all_chi_squareds.index(min(all_chi_squareds))
    return chr(shift + 97)


def get_key(ciphertext, key_length):
    key = ''

    # Calculate letter frequency table for each letter of the key
    for i in range(key_length):
        sequence = ""
        for j in range(0, len(ciphertext[i:]), key_length):
            sequence += ciphertext[i + j]
        key += frequency_analysis(sequence)
    return key


def decrypt(ciphertext, key):
    cipher_ascii = [ord(letter) for letter in ciphertext]
    key_ascii = [ord(letter) for letter in key]
    plain_ascii = []

    for i in range(len(cipher_ascii)):
        plain_ascii.append(((cipher_ascii[i] - key_ascii[i % len(key)]) % 26) + 97)

    plaintext = ''.join(chr(i) for i in plain_ascii)
    return plaintext


def main():
    ciphertext = ''.join(x.lower() for x in 'PATGSJKGSPFPCTSSKHOIGSDHNBCUHVIHKSHVBKPBQLEGVFSHPLTQFLYRWSRLYBSSRPPPPGIUOTUSHVPTZSVLNBCHCIWMIZSZKPWWZLZKXJWUCMWFCBCAACBKKGDBHOAPPMHVBKPBQLDXKWGPPXSZCUZHCNCVWGSOGRAWIVSTPHROFLBHGHVLYNQIBAEEWWGYAMJFBDDBRVVLKIIWAPOMXQOSHRPBHPYBEOHLZPDIZKXXCCZVJZTFHOWGIKCDAXZGCMYHJFGLPATKOYSTHBCAPHTBRZKJJWQRHR' if x.isalpha())

    ic = get_index_coincidence(ciphertext)
    print(f"Index of coincidence: {ic}")

    key_length = get_key_length(ciphertext)
    print(f"Key length: {key_length}")

    key = get_key(ciphertext, key_length)
    plaintext = decrypt(ciphertext, key)

    print(f"Key: {key}")
    print(f"Plaintext: {plaintext}")

if __name__ == '__main__':
    main()
