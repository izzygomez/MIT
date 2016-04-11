import requests
import gmpy2
import sys
import math
import json

n = 1024
R = 2**(n//2)


SERVER_URL = "http://6857rsa.csail.mit.edu:8080"
TEAM = "izzyg,bsaavedr,jyucra"
# TEAM = "PRACTICE_b25d7ad58b9ae50b"

#
#   Dependency Notes:
#       This file requires python3 and the gmp library. It also requires the pip
#       module gmpy2.
#
#       First check google for instructions on how to install python3 and gmp
#       for your operating system. They are available with apt-get on Linux and
#       brew on mac.
#
#       Next make sure pip is installed (using python3 not python):
#           https://pip.pypa.io/en/stable/installing/
#
#       Finally install gmpy2
#           python3 -m pip install gmpy2
#
#       If you are using windows, make sure you have Python3.2 or Python3.3
#           installed, then run the appropriate installer from
#           https://pypi.python.org/pypi/gmpy2 to install gmpy2.
#
#       Feel free to post on piazza for assistance!
#

#
#   RSA Server API
#   POST /decrypt
#       json request body
#           team: String, comma-separated list of team member kerberos names (or
#               a practice team name previously generated by the server)
#           ciphertext: String, hex-encoded
#           no_n: bool, optional, if true the server omits the modulus in the response
#               setting this will save some network bandwidth if you already
#               know the modulus for this team strings's key
#       json response body
#           modulus: String, hex-encoded, present if no_n was not true
#           time: integer, units of time the decryption took (use this, not the
#               real time the response takes to arrive)
#
#   POST /guess
#       json request body
#           team: String
#           q: String, hex-encoded, the smaller of (p, q)
#       json response body
#           correct: bool, whether the guess is correct
#
#   GET /gen_practice
#       no request body
#       json response body
#           team: String, a random team string generated by the server
#           p: String, hex-encoded, the larger of the two secret primes
#           q: String, hex-encoded, the smaller of the two secret primes
#

def main():

    guessnum = 512-16

    #   first make a dummy request to find the public modulus for our team
    initial_request = {"team": TEAM, "ciphertext": "00"*(n//8)}
    r = requests.post(SERVER_URL + "/decrypt", data=json.dumps(initial_request))
    try:
        N = int(r.json()["modulus"], 16)
    except:
        print(r.text)
        sys.exit(1)

    #   compute R^{-1}_N
    Rinv = gmpy2.invert(R, N)

    #   Start with a "guess" of 0, and analyze the zero-one gap, updating our
    #   guess each time. Repeat this for the (512-16) most significant bits of q
    g = gmpy2.mpz(0)

    for i in range(guessnum): # used to be range(512 - 16)
        print(i)
        gap = compute_gap(g, i, Rinv, 50, N)

        #   TODO: based on gap, decide whether bit (512 - i) is 0 or 1, and
        #   update g accordingly
        if gap<600: # bit is 1
            g = g+2**(512-i)

    # Off-by-one error somewhere, and this line saves our ass somehow
    g = gmpy2.c_div(g, 2)

    # print("bin(g): ", str(bin(g)))

    # HARDCODED SOLUTION (used for testing purposes)
    # hs = int("0b11111000110110011111100101100001110010001001010010111010011100010110001010000001001001001010011111101110010111000011101011011111110010011111100100111011101001011100011110001111011011000011011111001111001011010100111110010110011010111001100110001100110110010110011111110010011111101001100100100001100000111111100010010001110111000000010000001001100010010000100100011100100100100100110111101011100101000000001011101111110101001100100001000110010101111101101011011100001001110010010010110001011010001000011000001001", 2)
    # hs_16_zeros = int("0b11111000110110011111100101100001110010001001010010111010011100010110001010000001001001001010011111101110010111000011101011011111110010011111100100111011101001011100011110001111011011000011011111001111001011010100111110010110011010111001100110001100110110010110011111110010011111101001100100100001100000111111100010010001110111000000010000001001100010010000100100011100100100100100110111101011100101000000001011101111110101001100100001000110010101111101101011011100001001110010010010110001011010000000000000000000", 2)
    # h = gmpy2.mpz(hs)
    # g = gmpy2.mpz(hs_16_zeros)
    # submit_guess(h)

    # brute-force last 16 bits
    print("Starting brute-force...")
    for i in range(2**16):
        q = g + i
        if N%q==0:    # check if this is a valid q
            print("GOT EM")
            print(str(bin(q)))
            submit_guess(q)

#   compute the gap for a given guess `g` (assuming the top `i` bits are
#   correct)
def compute_gap(g, i, Rinv, n, N):
    #   TODO: compute `g_hi`, `u_g`, and `u_{g_hi}` as in [BB05] Section 3, take
    #   average time over neighborhoods (n = 50 is a good starting point) for
    #   `u_g` and `u_{g_hi}`, and compute the gap

    g_hi = g + 2**(512-i)

    # calculate decrypt time for u_g and u_g_hi (in neighborhood)
    dec_results_u_g_SUM = 0
    dec_results_u_g_hi_SUM = 0
    for i in range(n):
        curr_g = g + i
        curr_g_hi = g_hi + i

        curr_u_g = (curr_g*Rinv)%N
        curr_u_g_hi = (curr_g_hi*Rinv)%N

        dec_results_u_g_SUM += time_decrypt(curr_u_g)
        dec_results_u_g_hi_SUM += time_decrypt(curr_u_g_hi)

    # take average over neighborhood
    avg_dec_u_g = dec_results_u_g_SUM/n
    avg_dec_u_g_hi = dec_results_u_g_hi_SUM/n
    gap = abs(avg_dec_u_g - avg_dec_u_g_hi)

    return gap

#   hex-encode a ciphertext and send it to the server for decryption
#   returns the simulated time the decryption took
def time_decrypt(ctxt):
    padded_ctxt = ctxt_to_padded_hex_string(ctxt, n)
    req = {"team": TEAM, "ciphertext": padded_ctxt, "no_n": True}
    r = requests.post(SERVER_URL + "/decrypt", data=json.dumps(req))
    try:
        return r.json()["time"]
    except:
        print(r.text)

#   converts a gmpy integer into a hex string front-zero padded to n bits
def ctxt_to_padded_hex_string(ctxt, n):
    h = ctxt.digits(16)
    h = "0"*max(n//4 - len(h), 0) + h
    return h

#   requests a random practice key from the server
def gen_practice_key():
    r = requests.get(SERVER_URL + "/gen_practice")
    try:
        json = r.json()
        return {"team": json["team"], "p": int(json["p"], 16), "q": int(json["q"], 16)}
    except:
        print(r.text)
        sys.exit(1)

#   hex-encodes q and sends it to the server, printing the result
def submit_guess(q):
    #   convert q to hex and remove '0x' at beginning
    data = {"team": TEAM, "q": hex(q)[2:]}
    r = requests.post(SERVER_URL + "/guess", data=json.dumps(data))
    print(r.text)

if __name__ == "__main__":
    main()
