#!/usr/bin/python

from random import randint
from textwrap import wrap
import base64
import sys

# Dramatis Personae
llen = 50                                                       # Line length
k = 10                                                        # Accuracy of the prime test
test_msg = 'The quick brown fox jumps over the lazy dog.\n'     # A message to test with
key_min = 1<<1024                                                 # Lower bound of keys
key_max = 1<<1025                                                 # Upper bound of keys

begin_pub_msg = '=====BEGIN PUBLIC KEY BLOCK=====\n'
end_pub_msg   = '=====END PUBLIC KEY BLOCK=====\n'
begin_prv_msg = '=====BEGIN PRIVATE KEY BLOCK=====\n'
end_prv_msg   = '=====END PUBLIC KEY BLOCK=====\n'
begin_cipher_msg = '=====BEGIN ENCIPHERED MESSAGE BLOCK=====\n'
end_cipher_msg = '=====END ENCIPHERED MESSAGE BLOCK=====\n'
key_sp = '#####'

# Act I. The Helper Functions

# Scene I. The Testers of Primality

def calc_sr(n):
	n = n-1
	r = 0
	while n%2 == 0:
		r = r+1
		n = n/2
	return (n, r)

def trivial_prime(n):
	return (n == 2) or (n == 3)

def is_prime(n):
	if n<=3 or (n%2 == 0):
		return trivial_prime(n)
	(s, r) = calc_sr(n)
	for _ in range(1, k):
		a = randint(2, n-2)
		x = pow(a, s, n)
		if (x == 1) or (x == n-1):
			continue
		for j in range(0, r-1):
			x = (x*x)%n
			if x == 1:
				return False
			elif x == n-1:
				break
		if x != n-1:
			return False
	return True

# Scene II. The Euclidean Algorithm

def gcd(a, b):
    while b != 0:
        (a, b) = (b, a%b)
    return a

def euclidean(a, b):
    print a,b
    (x, lx) = (0, 1)
    while b != 0:
        q = a//b
        (a, b) = (b, a%b)
        (x, lx) = (lx - q*x, x)
    return lx

def are_coprime(a, b):
    return gcd(a, b) == 1

# Scene III. Randomizers

def rand_prime(lb, ub):
    a = 0
    while not(is_prime(a)):
        a = randint(lb, ub)
    return a

def first_coprime(lb, ub, cp_to):
    a = lb
    while (not(is_prime(a))) or (not(are_coprime(a, cp_to))):
        a = a+1
    return a

# Scene IV. The Humble Encoding Scheme

def dec(b):
    return int(b, 2)

def b64num(num):
    return base64.b64encode(str(num))

def numb64(b64):
    return long(base64.b64decode(b64))

# Act II. Generating Keys

# Scene I. The Keymaker

def gen_keys(k_min, k_max):
    print "Generating keys, please wait..."
    print "This may take a long time, so get yourself a cup of coffee!"
    p = rand_prime(k_min,k_max)
    q = rand_prime(k_min,k_max)
    n = p*q
    phi = (p-1)*(q-1)
    e = first_coprime(2, phi-1, phi)
    d = euclidean(e, phi)
    while d<0:
        d = d+phi

    print (p, q, n, e, d)

    q_key = wrap(b64num(n) + key_sp + b64num(e), llen)
    q_prv = wrap(b64num(n) + key_sp + b64num(d), llen)

    while True:
        usr_inp = raw_input("Save the keys to file (Y/n)? ")
        if usr_inp == "" or usr_inp == "y" or usr_inp == "Y":
            fname = raw_input("Enter public key file name: ")
            f = open(fname, 'w')
            f.write(begin_pub_msg)
            for line in q_key:
                f.write(line + '\n')
            f.write(end_pub_msg)
            fname = raw_input("Enter private key file name: ")
            f = open(fname, 'w')
            f.write(begin_prv_msg)
            for line in q_prv:
                f.write(line + '\n')
            f.write(end_prv_msg)
            print "Done! Keep your private key safe and give out your public key."
            return
        elif usr_inp == "n" or usr_inp == "N":
            return
        else:
            print "Invalid option. Enter Y or N.\n"

# Act III. The Enciphering of Messages

# Scene I. A Padding Scheme

def pad(msg):
    lmsg = map(ord, list(msg))
    count = 0
    result = 0
    for i in lmsg:
        result = result + i*(256**count)
        count = count+1
    return result

# Scene II. The Business of Enciphering

def read_key():
    while True:
        usr_inp = raw_input("Load public key from file (Y/n)? ")
        if usr_inp == "" or usr_inp == "y" or usr_inp == "Y":
            fname = raw_input("Enter public key file name: ")
            f = open(fname, 'r')
            pub = f.read().replace(begin_pub_msg, '').replace(end_pub_msg, '').replace('\n', '').split(key_sp)
            return map(numb64, pub)
        elif usr_inp == "n" or usr_inp == "N":
            print "Entering public key by hand (NOT RECOMMENDED!) Enter <c-d> after newline to terminate."
            return map(numb64, sys.stdin.read().replace(begin_pub_msg, '').
                    replace(end_pub_msg, '').replace('\n', '').split(key_sp))
            break
        else:
            print "Invalid option. Enter Y or N.\n"

def enc_msg():
    print "We need the public key of the recipient."
    (n, e) = read_key()
    while True:
        usr_inp = raw_input("Load message to encipher from file (Y/n)? ")
        if usr_inp == "" or usr_inp == "y" or usr_inp == "Y":
            fname = raw_input("Enter message file name: ")
            f = open(fname, 'r')
            msg = f.read()
            break
        elif usr_inp == "n" or usr_inp == "N":
            print "Reading message from command line. Enter <c-d> after newline to terminate."
            msg = sys.stdin.read()
            print
            break
        else:
            print "Invalid option. Enter Y or N.\n"

    print "Enciphering, please wait..."
    lenc = []
    while len(msg) > 255:
        blk = msg[:255]
        padded_blk = pad(blk)
        enc_blk = pow(padded_blk, e, n)
        lenc.append(enc_blk)
        msg = msg[256:]

    padded_msg = pad(msg)
    encrypted = pow(padded_msg, e, n)
    lenc.append(encrypted)
    q_enc = wrap(''.join(map(lambda s: s+key_sp, map(b64num, lenc))), llen)

    print 'Enciphered message:\n'
    print begin_cipher_msg[:-1]
    for line in q_enc:
        print line
    print end_cipher_msg

    while True:
        usr_inp = raw_input("Save enciphered message to file (Y/n)? ")
        if usr_inp == "" or usr_inp == "y" or usr_inp == "Y":
            fname = raw_input("Enter file name: ")
            f = open(fname, 'w')
            f.write(begin_cipher_msg)
            for line in q_enc:
                f.write(line + '\n')
            f.write(end_cipher_msg)
            break
        elif usr_inp == "n" or usr_inp == "N":
            break
        else:
            print "Invalid option. Enter Y or N.\n"

# Act IV. The Deciphering of Messages

# Scene I. Decode and De-pad

def depad(num):
    lmsg = []
    while num > 256:
        lmsg.append(num%256)
        num = num//256
    lmsg.append(num)
    return ''.join(map(chr, lmsg))

# Scene II. The Business of Deciphering

def read_prv():
    while True:
        usr_inp = raw_input("Load private key from file (Y/n)? ")
        if usr_inp == "" or usr_inp == "y" or usr_inp == "Y":
            fname = raw_input("Enter private key file name: ")
            f = open(fname, 'r')
            pub = f.read().replace(begin_prv_msg, '').replace(end_prv_msg, '').replace('\n', '').split(key_sp)
            return map(numb64, pub)
        elif usr_inp == "n" or usr_inp == "N":
            print "Entering private key by hand (NOT RECOMMENDED!) Enter <c-d> after newline to terminate."
            return map(numb64, sys.stdin.read().replace(begin_prv_msg, '').
                    replace(end_prv_msg, '').replace('\n', '').split(key_sp))
            break
        else:
            print "Invalid option. Enter Y or N.\n"

def dec_msg():
    print "We need the private key to decipher the message."
    (n, d) = read_prv()
    while True:
        usr_inp = raw_input("Load message to decipher from file (Y/n)? ")
        if usr_inp == "" or usr_inp == "y" or usr_inp == "Y":
            fname = raw_input("Enter message file name: ")
            f = open(fname, 'r')
            msg = f.read()
            break
        elif usr_inp == "n" or usr_inp == "N":
            print "Reading message from command line. Press <c-d> twice to terminate."
            msg = sys.stdin.read()
            print
            break
        else:
            print "Invalid option. Enter Y or N.\n"

    msg = msg.replace(begin_cipher_msg, '').replace(end_cipher_msg, '').replace('\n', '').split(key_sp)[:-1]
    lmsg = map(numb64,msg)
    print "Deciphering, please wait..."
    clearnum = map(lambda num: pow(num, d, n), lmsg)
    cleartxt = ''.join(map(depad, clearnum))
    print "The deciphered message is:\n"
    print cleartxt
    while True:
        usr_inp = raw_input("Save this message to file (y/N)? ")
        if usr_inp == "y" or usr_inp == "Y":
            fname = raw_input("Enter message file name: ")
            f = open(fname, 'w')
            f.write(cleartxt)
            break
        elif usr_inp == "" or usr_inp == "n" or usr_inp == "N":
            break
        else:
            print "Invalid option. Enter Y or N.\n"

# Act V. The Main Function

# Scene V. The Main Function

def main():
    print "RSA Cryptosystem Implementation"
    while True:
        print "Main menu\n"
        print "1) Generate key pairs"
        print "2) Encipher a message"
        print "3) Decipher a message"
        print "4) Exit\n"
        usr_inp = raw_input("Please choose one: ")
        if usr_inp == '1':
            gen_keys(key_min, key_max)
            print
        elif usr_inp == '2':
            enc_msg()
            print
        elif usr_inp == '3':
            dec_msg()
            print
        elif usr_inp == '4':
            return
        else:
            print "Invalid option.\n"

main()
