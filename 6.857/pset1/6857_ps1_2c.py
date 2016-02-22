# 6.857 pset 1
import string
import ffield

# Given ciphertexts
eight_ciphs = """50 90 5f 98 db 20 fb 0a 7a 1c 8b 71 14 f7 e4 b1 b2 8b 63 a6 f7 3d 8a 46 e2 c6 a7 51 1f 97 7e fe 71 b8 36 3c cd 20 89 df
2a 5a fe 23 db bb 9e ba 5d 42 3b c8 f9 0b 97 18 1f b5 06 7e cf 18 d2 0b d5 f6 e5 75 d4 7f ea 65 27 b8 9a d4 ca cd de 37
b5 2f 00 98 89 85 fb 8d d5 00 d1 df 26 33 91 ce d5 bb 9a 61 42 6a c9 21 58 57 a7 7b 47 57 55 21 f8 9b d9 d3 ca 41 de 1c
11 4d 2a 70 2b 02 f3 48 d9 cc 7e c8 97 c4 7b f6 73 b5 b5 0b 69 65 ff 47 d5 c3 a7 7d 61 5b a6 a3 bb b8 8f d4 71 da 84 cb
fd 5e be ea 45 3d 9e 48 a9 b6 f2 c2 26 f4 7f ea 1f e8 ba 79 7e 73 88 38 58 e3 a7 7b b5 4c 32 bc 91 85 4a d3 6b b3 0d b5
50 2f b4 ed 6e 3d 63 9e 7a 1c a4 71 f9 f0 52 ce 0f 35 e5 02 2c 18 93 f7 f3 9c a7 7d b5 97 4d 00 7a 55 d9 d4 18 41 82 c6
11 70 f6 85 38 02 17 e1 06 6f 3b f6 7a 0b 93 5e 0f a8 2f 61 69 18 ee a2 57 3d 73 4b df c7 55 7c 27 3e a5 e5 8d a6 4f 37
50 63 f6 84 fa 7c 63 77 5e 6f 8b c8 26 f7 46 b1 1f bb 9a 61 7e 18 8a e8 d5 53 a7 d3 1f 4c 55 ae 7a b8 3e e5 cd 41 84 e5"""

# format cipher texts. all_ciphs is a list of all 8 ciphers,
# each one represented as a list of it's 40 message bytes
all_ciphs = string.split(eight_ciphs, "\n")
for i in xrange(len(all_ciphs)):
    all_ciphs[i] = string.split(all_ciphs[i], " ")

# create pad hex bytes
hexdigits = string.hexdigits[:-6]
possible_pad_bytes = [i + j for i in hexdigits for j in hexdigits]

# Initialize finite field GF(8)
F = ffield.FField(8)

# Helper functions for computations
def hex2dec(hex_string):
    '''converts hex value to dec'''
    return int(hex_string, 16)

def dec2hex(dec):
    '''converts int to hex string W/OUT '0x' in front'''
    return hex(dec)[2:]

def resolve_mi(ci_hex, pi_hex, qi_hex):
    '''given hex-valued values ci, pi, and qi, return mi,
       after resolving for it in the equation
       ci = pi * mi + qi (all within GZ(8)),
       in hex form'''
    ci = hex2dec(ci_hex)
    pi = hex2dec(pi_hex)
    qi = hex2dec(qi_hex)
    ci_minus_qi = F.Subtract(ci, qi)
    ci_minus_qi_divided_pi = F.DoDivide(ci_minus_qi, pi)
    mi = ci_minus_qi_divided_pi
    mi_hex = dec2hex(mi)
    return mi_hex

def is_possible_character(hex_string):
    '''checks if given hex string represents ascii value a-z or space'''
    dec = hex2dec(hex_string)
    if dec==32 or (dec >= 97 and dec<=122):
        return True
    return False

# list of lists of possible solutions for each byte
global_solution_pi = []
global_solution_qi = []

# Do brute force reverse engineering
# NOTE: can comment this section out and use the precomputed, hardcoded
# results in the following section
for number_byte in xrange(40): # size of our messages are 40
    solution_pi = []
    solution_qi = []
    for pi_guess in possible_pad_bytes:
        for qi_guess in possible_pad_bytes:
            count = 0
            for some_cipher in all_ciphs:
                ci_hex = some_cipher[number_byte]
                mi_guess = resolve_mi(ci_hex, pi_guess, qi_guess)
                if is_possible_character(mi_guess):
                    count += 1
            if count==8:
                solution_pi.append(pi_guess)
                solution_qi.append(qi_guess)
    global_solution_pi.append(solution_pi)
    global_solution_qi.append(solution_qi)

# HARDCODED SOLUTIONS: these are the solutions that are eventually computed for
# global_solution_pi and global_solution_qi. I'm including these here to not
# have to recalculate these solutions everytime you run the script; instead,
# comment out the last section that does all the computation and uncomment
# these two solutions
# global_solution_pi = [['24'], ['85'], ['4a'], ['80'], ['19'], ['63'], ['17'], ['b0'], ['e1'], ['33'], ['75'], ['63'], ['7d'], ['f7'], ['2d'], ['0e'], ['68'], ['a1'], ['bc'], ['29'], ['19'], ['57'], ['05'], ['2a'], ['8c'], ['25'], ['1a', '32', '35', '35', '35', '35', '35', '35', '35', '35', '35', '35', '35', '35', '35', '35', '35', '35', '4a', '72', '72', '72', '72', '72', '72', '72', '72', '72', '72', '72', '72', '72', '72', '72', '72', '72', '72', '92', '9a', 'b0', 'c8', 'c8', 'c8', 'c8', 'c8', 'c8', 'c8', 'c8', 'c8', 'c8', 'c8', 'c8', 'c8', 'c8', 'c8', 'c8', 'cf', 'd4', 'fa'], ['02'], ['26'], ['0c'], ['cd'], ['fe'], ['df'], ['bb'], ['7c'], ['83', 'ef'], ['a0'], ['7c'], ['21'], ['3f']]

# global_solution_qi = [['e5'], ['42'], ['43'], ['27'], ['8e'], ['47'], ['b9'], ['cb'], ['2f'], ['41'], ['8d'], ['34'], ['3d'], ['7c'], ['8f'], ['6c'], ['9e'], ['22'], ['84'], ['28'], ['79'], ['2a'], ['2a'], ['c1'], ['85'], ['87'], ['c0', '7d', '03', '08', '1e', '2b', '36', '3d', '41', '62', '69', '74', '95', 'a0', 'bd', 'd7', 'e2', 'ff', '50', '06', '07', '26', '36', '37', '45', '54', '64', '74', '75', '91', 'a0', 'a1', 'b0', 'd3', 'e2', 'e3', 'f2', '10', 'd9', '24', '20', '27', '29', '3c', '62', '65', '79', '7e', 'a4', 'aa', 'b1', 'b6', 'e1', 'e8', 'f3', 'f4', '3d', '7a', 'd3'], ['93'], ['ab'], ['d1'], ['cd'], ['18'], ['98'], ['46'], ['05'], ['79', '49'], ['74'], ['7a'], ['d0'], ['56']]

# I'm arbitrarily choosing the first found solution for each message byte as
# the correct one. As you can see from the hardcoded solutions above, this'll
# be the only option for many bytes; for those bytes that have multiple options,
# this choice might not be the correct one (obviously). We'll decipher what
# remains using human intuition and the surrounding context clues in the
# decrypted messages
global_solution_pi = [i[0] for i in global_solution_pi]
global_solution_qi = [i[0] for i in global_solution_qi]

# Realized that our previous choice of arbitrarily choosing the first found
# solution for each message byte was a good choice, with the exception of the
# 5th to last byte. It's correct mi is resolved when the second solution is
# used, which is what I'm hardcoding with this:
global_solution_pi[-5] = 'ef'
global_solution_qi[-5] = '49'

# Decrypt each ciphertext in order and print out
for some_cipher in all_ciphs:
    decrypted_message = []
    for i in xrange(40):
        decrypted_byte_hex = resolve_mi(some_cipher[i], global_solution_pi[i], global_solution_qi[i])
        decrypted_message.append(chr(hex2dec(decrypted_byte_hex)))
    print "\""+''.join(decrypted_message)+"\""
