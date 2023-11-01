
###############functions#####################

def BinaryToHexadecimal(binaryString): 
    if len(binaryString) % 4 != 0:
        raise ValueError("The length of  input binary string must be a multiple of 4") 
    hex_string = hex(int(binaryString, 2))[2:].upper()
    return hex_string

def HexadecimalToBinary(hexString):
    binary_string = ""
    for char in hexString:
        binary_char = bin(int(char, 16))[2:].zfill(4)
        binary_string += binary_char
    return binary_string


def matrixmultiplication(a, b):
    a=int(a,2)
    b=int(b,2)

    m = 0
    while (b > 0):
        if (b & 0b0001):   
            m = m ^ a # biy wise and opeartor wihh 1 to check LSB
        if (a & 0b1000):
            a = a << 1  
            a =a^ 0b10011
        else:  # bit wise and opeartor with 1 to check 4th bit
            a = a << 1
        b =b>> 1  # Right shift b by 1
    return m



def subNibble(nibblestr):
    return dict1[nibblestr]

def subNibbleForDecryption(nibblestr):
    return dict2[nibblestr]


def xorfunction(string1,string2):
    x=bin(string1^string2)[2:].zfill(16)
    return x


def shifRows(string):
    string=list(string)
    temp=string[:8]
    string[:8]=string[8:]
    string[8:]=temp
    temp=string[4:8]
    string[4:8]=string[12:16]
    string[12:16]=temp
    string="".join(string)
    return (string)

def generateRoundKeys(key):
    genkey1=[]
    genkey2=[]
    Rcon1="1110"
    Rcon2="1010"
    genkey1.append(bin(int(key[0:4],2)^int(subNibble(key[12:16]),2)^int(Rcon1,2))[2:].zfill(4))
    genkey1.append(bin(int(key[4:8],2)^int(genkey1[0],2))[2:].zfill(4))
    genkey1.append(bin(int(key[8:12],2)^int(genkey1[1],2))[2:].zfill(4))
    genkey1.append(bin(int(key[12:16],2)^int(genkey1[2],2))[2:].zfill(4))


    genkey2.append(bin(int(genkey1[0],2)^int(subNibble(genkey1[-1]),2)^int(Rcon2,2))[2:].zfill(4))
    genkey2.append(bin(int(genkey1[1],2)^int(genkey2[0],2))[2:].zfill(4))
    genkey2.append(bin(int(genkey1[2],2)^int(genkey2[1],2))[2:].zfill(4))
    genkey2.append(bin(int(genkey1[3],2)^int(genkey2[2],2))[2:].zfill(4))

    genkey1="".join(genkey1)
    genkey2="".join(genkey2)
    return [genkey1,genkey2]


def mixColumns(string,choice):
    mixCol_result=""
    if(choice=='1'):
        matrix=matrix1
    else:
        matrix=matrix2
    res1=matrixmultiplication(matrix[0],string[:4])
    res2=matrixmultiplication(matrix[2],string[4:8])
    mixCol_result=helperFunctionForMixCols(res1,res2)

    res1=matrixmultiplication(matrix[1],string[:4])
    res2=matrixmultiplication(matrix[3],string[4:8])
    valueToAdd=helperFunctionForMixCols(res1,res2)
    mixCol_result=mixCol_result+valueToAdd


    res1=matrixmultiplication(matrix[0],string[8:12])
    res2=matrixmultiplication(matrix[2],string[12:])
    valueToAdd=helperFunctionForMixCols(res1,res2)
    mixCol_result=mixCol_result+valueToAdd

    res1=matrixmultiplication(matrix[1],string[8:12])
    res2=matrixmultiplication(matrix[3],string[12:])
    valueToAdd=helperFunctionForMixCols(res1,res2)
    mixCol_result=mixCol_result+valueToAdd
    return mixCol_result


def helperFunctionForMixCols(res1,res2):
    valueToAdd=res1^res2
    valueToAdd=str(bin(valueToAdd)[2:]).zfill(4)
    return valueToAdd

###############dictionary and matrix ##################

keys=['0000','0001','0010','0011','0100','0101','0110','0111','1000','1001','1010','1011','1100','1101','1110','1111']
values=['1010','0000','1001','1110','0110','0011','1111','0101','0001','1101','1100','0111','1011','0100','0010','1000']
dict1=dict(zip(keys,values))
dict2=dict(zip(values,keys))

matrix1=["0001","0100","0100","0001"]
matrix2=["1001","0010","0010","1001"]



#-----------------------------------------------------------------------------------------------------------------


def EncryptFunctionsTest():
    textblock=input("Enter a text block: ")
    while(len(textblock)>4):
        textblock=input("Enter a text block: ")
    if(len(textblock)<4):
        textblock=textblock.zfill(4)
    key=input("Enter a key: ")
    while(len(key)>4):
        key=input("Enter a key: ")
    if(len(key)<4):
        key=key.zfill(4)
    textblock_binary=HexadecimalToBinary(textblock)
    key_binary=HexadecimalToBinary(key)
    ########## 1- Sub nibble process #############
    subNibble_string=''
    for i in range(0,16,4):
        subNibble_string=subNibble_string+subNibble(textblock_binary[i:i+4])
    print("SubNibbles ("+textblock+"): ", BinaryToHexadecimal(subNibble_string))
    ############# 3 mix columns #############
    mixCol_result=mixColumns(textblock_binary,'1')
    print("MixColumns ("+textblock+"): ",BinaryToHexadecimal(mixCol_result))
    ########## 4- shift rows ###################
    shifted_string=shifRows(textblock_binary)
    result=BinaryToHexadecimal(shifted_string)
    print("ShiftRow ("+textblock+"): ",result)
    ########### -5 generate keys ############
    genkeys=generateRoundKeys(key_binary)
    print("GenerateRoundKeys ("+key+"): ","("+BinaryToHexadecimal(genkeys[0])+",",BinaryToHexadecimal(genkeys[1])+")")





def DecryptionAlgorithm():

    cipherblock=input("Enter a ciphertext block: ")
    while(len(cipherblock)>4):
        cipherblock=input("Enter a ciphertext block: ")
    if(len(cipherblock)<4):
        cipherblock=cipherblock.zfill(4)
    key=input("Enter the key: ")
    while(len(key)>4):
        key=input("Enter the key: ")
    if(len(key)<4):
        key=key.zfill(4)
    cipherblock_binary=HexadecimalToBinary(cipherblock)
    key_binary=HexadecimalToBinary(key)
    
    genkeys=generateRoundKeys(key_binary)
    #print("GenerateRoundKeys ("+key+"): ","(",BinaryToHexadecimal(genkeys[0]),",",BinaryToHexadecimal(genkeys[1])+")")
    ########### 1- shifting ################
    shifted_string=shifRows(cipherblock_binary)
    #print("Result after shifting in hex: ",BinaryToHexadecimal(shifted_string))
    ########### 2 - xor round key###########
    xored_string=xorfunction(int(shifted_string,2),int(genkeys[1],2)).zfill(16)
    #print("AddRoundKey ("+cipherblock+"): ",BinaryToHexadecimal(xored_string))
    ##########  3 Sub nibble process #############
    subNibble_string=''
    for i in range(0,16,4):
        subNibble_string=subNibble_string+subNibbleForDecryption(xored_string[i:i+4])
    value=BinaryToHexadecimal(subNibble_string)
    #print("Text after sub nibble process in hex: ", value)
    ########### 4 shifting ################
    shifted_string=shifRows(subNibble_string)
    #print("Result after shifting in hex: ",BinaryToHexadecimal(shifted_string))
    ########### 5 mixed column ################
    mixCol_result=mixColumns(shifted_string,'2')
    #print("Result from mixed columns step: ",BinaryToHexadecimal(mixCol_result))
    ########### 6- xor round key###########
    xored_string=xorfunction(int(mixCol_result,2),int(genkeys[0],2)).zfill(16)
    #print("AddRoundKey ("+cipherblock+"): ",BinaryToHexadecimal(xored_string))
    ########## 7- Sub nibble process #############
    subNibble_string=''
    for i in range(0,16,4):
        subNibble_string=subNibble_string+subNibbleForDecryption(xored_string[i:i+4])
    value=BinaryToHexadecimal(subNibble_string)
    #print("Text after sub nibble process in hex: ", value)

    print("Decrypted block: ",value)





def DecryptionAlgorithm_ASCII():
    print("Reading encrypted file....")
    key=input("Enter the decryption key: ")
    while(len(key)>4):
        key=input("Enter the decryption key: ")
    if(len(key)<4):
        key=key.zfill(4)
    f2=open("plain.txt","w")
    f1=open('secret.txt',"r")
    content=f1.read()
    contentList=content.split()
    result=""

    for cipherblock in contentList:
        cipherblock_binary=HexadecimalToBinary(cipherblock)
        key_binary=HexadecimalToBinary(key)
        genkeys=generateRoundKeys(key_binary)
        shifted_string=shifRows(cipherblock_binary)
        xored_string=xorfunction(int(shifted_string,2),int(genkeys[1],2)).zfill(16)
        subNibble_string=''
        for i in range(0,16,4):
            subNibble_string=subNibble_string+subNibbleForDecryption(xored_string[i:i+4])
        value=BinaryToHexadecimal(subNibble_string)
        shifted_string=shifRows(subNibble_string)
        mixCol_result=mixColumns(shifted_string,'2')
        xored_string=xorfunction(int(mixCol_result,2),int(genkeys[0],2)).zfill(16)
        subNibble_string=''
        for i in range(0,16,4):
            subNibble_string=subNibble_string+subNibbleForDecryption(xored_string[i:i+4])
        value=BinaryToHexadecimal(subNibble_string)

        if(value[2:]=='00'):
            value=value[:2]
        # print(len(value))
        ascii= bytes.fromhex(value).decode('ascii')
        f2.write(ascii)
        result=result+ascii

    print("Decrypted Result")
    print("--------------------")
    print(result)
    print("--------------------")
    f1.close()
    f2.close()



#------------------------------------------------------------------------------------------------------------------





while(True):
    print('\n')
    print("Press 1 to encrypt")
    print("Press 2 to decrypt")
    print("Press 3 to ecrypt or decrypt a file")
    print("Press 4 to exit")

    choice=input("Enter: ")
    if(choice=='1'):
        EncryptFunctionsTest()
    elif choice=='2':
        DecryptionAlgorithm()
    elif choice =='3':
        DecryptionAlgorithm_ASCII()
    elif choice=='4':
        break




