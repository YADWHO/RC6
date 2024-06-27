#RC6 

import math
# import sys


#rotate right input x, by n bits

def ROR(x, n, bits=32):
    mask = (1 << n) - 1   #Create a mask with the rightmost n bits set to 1
    mask_bits = x & mask  #Extract the rightmost n bits from x using the mask
    return ((x >> n) | (mask_bits << (bits - n))) & ((1 << bits) - 1)
    #shift the extracted bits to left to fill empty positions
    #and rotating right by x>>n and oring it with shifted bits
    #and masking it with (1<<bits-1 or 2**n-1 to keep the size)


#rotate left input x, by n bits

    
def ROL(x, n, bits=32):
    mask = (1 << n) - 1   #Create a mask with the rightmost n bits set to 1
    mask_bits = (x >> (bits - n)) & mask #Extract the rightmost n bits from x using the mask
    return ((x << n) | mask_bits) & ((1 << bits) - 1)
    #shift the extracted bits to left to fill empty positions
    #and rotating left by x<<n and oring it with shifted bits
    #and masking it with (1<<bits-1 or 2**n-1 to keep the size)




#convert input sentence into blocks of binary
def blockConverter(sentence):
    encoded = []  #to represent blocks

    for i in range(0, len(sentence), 4):  #to read 4 characters at a time
        block = ''.join(format(ord(char), '08b') for char in sentence[i:i+4])
        #for each character its ascii value is converted into 8bit format 
        #so total 8*4=32 bit string is created
        encoded.append(block) #the string is added

    return encoded
    
    
def blockConverter1(sentence): #for binary
    encoded = []

    for i in range(0, len(sentence), 32):  #this just takes 32*4 and puts them in a list
        block = sentence[i:i + 32]
        encoded.append(block)

    return encoded

#converts 4 blocks array of long int into string
def deBlocker(blocks):
    s=""   #s is initialised
    for ele in blocks:  #for each string in blocks
        binary_representation=bin(ele)[2:]  #it is converted into binary 2: removes the 0b
        if len(binary_representation) <32: #if length is less than 32 ,then it is made 32 bits by addinadding zeroes to left
            binary_representation = "0"*(32-len(binary_representation)) + binary_representation
            
     
        
        for i in range(0, 4): #there are four characters in that string (initial),so it requires 4 iterations
            start_index = i * 8
            end_index = (i+1) * 8
            s =s+ chr(int(binary_representation[start_index:end_index], 2)) #int with 2 converts it into decimal value and chr converts it into a character

    return s

def deBlocker1(blocks):  #for binary
    s = ""
    for ele in blocks:
        binary_representation = bin(ele)[2:]
        if len(binary_representation) < 32:
            binary_representation = "0" * (32 - len(binary_representation)) + binary_representation
        s += binary_representation

    return s


#converts 4 blocks array of long int into string
#generate key s[0... 2r+3] from given input string userkey
def generateKey(userkey):
    rounds=12  #number of rounds
    wordsize=32  #word size in bits
    b=len(userkey)
    modulo = 2**32  #for modulus
    s=[]  #list to store key schedule
    s.append(0xB7E15163)  #initialize the key schedule with first value
    prev=0xB7E15163    #keep track of previous value
    for i in range(1,2*rounds+4):
        a=((prev+0x9E3779B9)%(2**wordsize))  #formula to generate key schedule
        s.append(a)
        prev=a
    encoded = blockConverter(userkey)   #converts the key to binary repesentatin blocks
    #print encoded
    enlength = len(encoded)
    l = []   #used to store bbinary represenation of keys
    for i in range(enlength,0,-1):
        l.append(int(encoded[i-1],2))

    v = 3*max(enlength,2*rounds+4)
    A=0
    B=0
    i=0
    j=0
    # Modify the key schedule based on the user key and other parameters
    for index in range(0,v):  
        s[i] = ROL((s[i] + A + B)%modulo,3,32)
        A=s[i]
        l[j] = ROL((l[j] + A + B)%modulo,(A+B)%32,32)
        B=l[j]
        i = (i + 1) % (2*rounds + 4)
        j = (j + 1) % enlength
    return s
    
def generateKey1(userkey):
    rounds = 12
    wordsize = 32
    b = len(userkey)
    modulo = 2 ** 32
    s = []
    s.append(0xB7E15163)
    prev = 0xB7E15163

    for i in range(1, 2 * rounds + 4):
        a = ((prev + 0x9E3779B9) % (2 ** wordsize))
        s.append(a)
        prev = a

    encoded = blockConverter1(userkey)
    enlength = len(encoded)
    l = []

    for i in range(enlength, 0, -1):
        l.append(int(encoded[i - 1], 2))

    v = 3 * max(enlength, 2 * rounds + 4)
    A = 0
    B = 0
    i = 0
    j = 0

    for index in range(0, v):
        s[i] = ROL((s[i] + A + B) % modulo, 3, 32)
        A = s[i]
        l[j] = ROL((l[j] + A + B) % modulo, (A + B) % 32, 32)
        B = l[j]
        i = (i + 1) % (2 * rounds + 4)
        j = (j + 1) % enlength
    return s

def encrypt(sentence,s):
    
    
    
#     // Encryption/Decryption with RC6-w/r/b
# // 
# // Input:   Plaintext stored in four w-bit input registers A, B, C & D
# // 	r is the number of rounds
# // 	w-bit round keys S[0, ... , 2r + 3]
# // 
# // Output: Ciphertext stored in A, B, C, D
# // 
# // '''Encryption Procedure:'''

# 	B = B + S[0]
# 	D = D + S[1]
# 	for i = 1 to r do
# 	{
# 		t = (B * (2B + 1)) <<< lg w
# 		u = (D * (2D + 1)) <<< lg w
# 		A = ((A ^ t) <<< u) + S[2i]
# 		C = ((C ^ u) <<< t) + S[2i + 1] 
# 		(A, B, C, D)  =  (B, C, D, A)
# 	}
# 	A = A + S[2r + 2]
# 	C = C + S[2r + 3]

    encoded = blockConverter(sentence)
    enlength = len(encoded)
    A = int(encoded[0],2)
    B = int(encoded[1],2)
    C = int(encoded[2],2)
    D = int(encoded[3],2)
    plain = []
    plain.append(A)
    plain.append(B)
    plain.append(C)
    plain.append(D)
    rounds=12
    wordsize=32
    modulo = 2**32
    lgw = 5
    B = (B + s[0])%modulo
    D = (D + s[1])%modulo
    for i in range(1,rounds+1):
        t_temp = (B*(2*B + 1))%modulo
        t = ROL(t_temp,lgw,32)
        u_temp = (D*(2*D + 1))%modulo
        u = ROL(u_temp,lgw,32)
        tmod=t%32
        umod=u%32
        A = (ROL(A^t,umod,32) + s[2*i])%modulo
        C = (ROL(C^u,tmod,32) + s[2*i+ 1])%modulo
        (A, B, C, D)  =  (B, C, D, A)
    A = (A + s[2*rounds + 2])%modulo
    C = (C + s[2*rounds + 3])%modulo
    cipher = []
    cipher.append(A)
    cipher.append(B)
    cipher.append(C)
    cipher.append(D)
    return plain,cipher
    
def encrypt1(sentence, s):
    encoded = blockConverter1(sentence)
    enlength = len(encoded)
    A = int(encoded[0], 2)
    B = int(encoded[1], 2)
    C = int(encoded[2], 2)
    D = int(encoded[3], 2)
    plain = []
    plain.append(A)
    plain.append(B)
    plain.append(C)
    plain.append(D)
    rounds = 12
    wordsize = 32
    modulo = 2 ** 32
    lgw = 5
    B = (B + s[0]) % modulo
    D = (D + s[1]) % modulo

    for i in range(1, rounds + 1):
        t_temp = (B * (2 * B + 1)) % modulo
        t = ROL(t_temp, lgw, 32)
        u_temp = (D * (2 * D + 1)) % modulo
        u = ROL(u_temp, lgw, 32)
        tmod = t % 32
        umod = u % 32
        A = (ROL(A ^ t, umod, 32) + s[2 * i]) % modulo
        C = (ROL(C ^ u, tmod, 32) + s[2 * i + 1]) % modulo
        (A, B, C, D) = (B, C, D, A)

    A = (A + s[2 * rounds + 2]) % modulo
    C = (C + s[2 * rounds + 3]) % modulo
    cipher = []
    cipher.append(A)
    cipher.append(B)
    cipher.append(C)
    cipher.append(D)
    return plain, cipher

#def decrypt(esentence,s):
def decrypt(encoded,s):
    # encoded = blockConverter(esentence)
    enlength = len(encoded)
    # A = int(encoded[0],2)
    # B = int(encoded[1],2)
    # C = int(encoded[2],2)
    # D = int(encoded[3],2)
    
    
    
# // '''Decryption Procedure:'''

# 	C = C - S[2r + 3]
# 	A = A - S[2r + 2]
# 	for i = r downto 1 do
# 	{
# 		(A, B, C, D) = (D, A, B, C)
# 		u = (D * (2D + 1)) <<< lg w
# 		t = (B * (2B + 1)) <<< lg w
# 		C = ((C - S[2i + 1]) >>> t) ^ u
# 		A = ((A - S[2i]) >>> u) ^ t
# 	}
# 	D = D - S[1]
# 	B = B - S[0]
    A = bin(encoded[0])[2:]  #toconvert to binary string
    B = bin(encoded[1])[2:]
    C = bin(encoded[2])[2:]
    D = bin(encoded[3])[2:]
    
    A = int(A,2)
    B = int(B,2)
    C = int(C,2)
    D = int(D,2)
    
    cipher = []
    cipher.append(A)
    cipher.append(B)
    cipher.append(C)
    cipher.append(D)
    rounds=12
    wordsize=32
    modulo = 2**32
    lgw = 5
    C = (C - s[2*rounds+3])%modulo
    A = (A - s[2*rounds+2])%modulo
    for j in range(1,rounds+1):
        i = rounds+1-j
        (A, B, C, D) = (D, A, B, C)
        u_temp = (D*(2*D + 1))%modulo
        u = ROL(u_temp,lgw,32)
        t_temp = (B*(2*B + 1))%modulo
        t = ROL(t_temp,lgw,32)
        tmod=t%32
        umod=u%32
        C = (ROR((C-s[2*i+1])%modulo,tmod,32)  ^u)
        A = (ROR((A-s[2*i])%modulo,umod,32)   ^t)
    D = (D - s[1])%modulo
    B = (B - s[0])%modulo
    plain = []
    plain.append(A)
    plain.append(B)
    plain.append(C)
    plain.append(D)
    return cipher,plain
    
def decrypt1(encoded, s): #for binary
    enlength = len(encoded)

    A = int(encoded[0],2)
    B = int(encoded[1],2)
    C = int(encoded[2],2)
    D = int(encoded[3],2)


    cipher = []
    cipher.append(A)
    cipher.append(B)
    cipher.append(C)
    cipher.append(D)
    rounds = 12
    wordsize = 32
    modulo = 2 ** 32
    lgw = 5
    C = (C - s[2 * rounds + 3]) % modulo
    A = (A - s[2 * rounds + 2]) % modulo

    for j in range(1, rounds + 1):
        i = rounds + 1 - j
        (A, B, C, D) = (D, A, B, C)
        u_temp = (D * (2 * D + 1)) % modulo
        u = ROL(u_temp, lgw, 32)
        t_temp = (B * (2 * B + 1)) % modulo
        t = ROL(t_temp, lgw, 32)
        tmod = t % 32
        umod = u % 32
        C = (ROR((C - s[2 * i + 1]) % modulo, tmod, 32) ^ u)
        A = (ROR((A - s[2 * i]) % modulo, umod, 32) ^ t)

    D = (D - s[1]) % modulo
    B = (B - s[0]) % modulo
    plain = []
    plain.append(A)
    plain.append(B)
    plain.append(C)
    plain.append(D)
    return cipher, plain
    

def get_binary_input(prompt):  #to get binary input and validate it
    binary_input = input(prompt)
    if not all(bit in '01' for bit in binary_input):
        raise ValueError("Invalid binary input. Please enter a valid binary string.")
    return binary_input



def display_menu():
    print("Menu:")
    print("1. Encrypt in string")
    print("2. Decrypt with list values")
    print("3. Encrypt in binary ")
    print("4. Decrypt in binary")
    print("5. Exit")


    

while True:
    display_menu()
    choice = input("Enter your choice (1-5): ")

    if choice == "1":
            
        key=input("Enter the key:")
        key = key + " " * (16 - len(key))
        key = key[:16]
        print("Key:\t" + key)
        s = generateKey(key)
            
        sentence=input("Enter the string to encrypt:")
        sentence = sentence + " " * (16 - len(sentence))
        sentence = sentence[:16]
            
        plain, cipher = encrypt(sentence, s)
        print("cipher",cipher)
        esentence = deBlocker(cipher)
      #  print("\nOriginal String list:",plain)
        print("Encrypted String:", esentence)
        print(type(esentence))
    elif choice == "2":
            
        key=input("Enter the key:")
        key = key + " " * (16 - len(key))
        key = key[:16]
        print("Key:\t" + key)
        s = generateKey(key)
        numbers_input = input("Enter a list of numbers separated by commas: ")
        encoded = [int(num) for num in numbers_input.split(",")]
        print(encoded)
        ## esentence=input("enter the cipher text:")
        cipher, plain = decrypt(encoded, s)
        #cipher, orgi = decrypt(esentence, s)
        sentence = deBlocker(plain)
        print("\nDecrypted:", sentence)
            
    if choice == "3":
        key = input("Enter the key in binary: ")
        key = "0" * (128 - len(key))+key   # Assuming a 128-bit key
        key = key[:128]
        print("Key:\t" + key)
        s = generateKey1(key)

        sentence = input("Enter the binary string to encrypt: ")
        sentence =  "0" * (128 - len(sentence))+sentence   # Assuming a 128-bit input
        sentence = sentence[:128]

        plain, cipher = encrypt1(sentence, s)
        print("Cipher:", cipher)
        esentence = deBlocker1(cipher)
      #  print("\nOriginal String list:", plain)
        print("Encrypted String:", esentence)

    elif choice == "4":
        key = input("Enter the key in binary: ")
        key = "0" * (128 - len(key)) +key  # Assuming a 128-bit key
        key = key[:128]

        print("Key:\t" + key)
        s = generateKey1(key)

        cipher_input = get_binary_input("Enter the binary cipher text: ")
        cipher, plain = decrypt1(blockConverter1(cipher_input), s)
        print("Decrypted String", deBlocker1(plain))


    elif choice == "5":
        print("Exiting program. Goodbye!")
        break  
        
    else:
        print("Invalid choice. Please enter a number between 1 and 5.")





#brute force

# def findUserKey(known_plaintext, known_ciphertext):
#     for key_candidate in range(2**31, 2**32):
#         print(key_candidate)
#         user_key_schedule = generateKey(format(key_candidate, '032b'))
#         encrypted = encrypt(known_plaintext, user_key_schedule)
#         if encrypted == known_ciphertext:
#             return user_key_schedule
#     return None

# # Example usage:
# key="A WORD IS A WORD"
# key = key + " " * (16 - len(key))
# key = key[:16]
# # print("Key:\t" + key)
# s = generateKey(key)
            
# sentence="I WORD IS A WORD"
# sentence = sentence + " " * (16 - len(sentence))
# sentence = sentence[:16]
            
# plain, cipher = encrypt(sentence, s)

# esentence = deBlocker(cipher)

# found_user_key_schedule = findUserKey(sentence, esentence)

# if found_user_key_schedule:
#     print("User Key Found:")
#     for i, value in enumerate(found_user_key_schedule):
#         print(f"s[{i}] = {hex(value)}")
# else:
#     print("User Key Not found")
