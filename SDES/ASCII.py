
class SDES_ASCII:
    '''
    S-DES加密类
    '''

    def __init__(self, key, P10=None, P8=None, IP=None, IP_INV=None, EP=None, S0=None, S1=None, P4=None):
        '''初始化加密类以及对应的密钥和各种转换盒'''
        self.key = key
        self.P10 = P10 if P10 is not None else [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
        self.P8 = P8 if P8 is not None else [6, 3, 7, 4, 8, 5, 10, 9]
        self.IP = IP if IP is not None else [2, 6, 3, 1, 4, 8, 5, 7]
        self.IP_INV = IP_INV if IP_INV is not None else [4, 1, 3, 5, 7, 2, 8, 6]
        self.EP = EP if EP is not None else [4, 1, 2, 3, 2, 3, 4, 1]
        self.S0 = S0 if S0 is not None else [
            [1, 0, 3, 2],
            [3, 2, 1, 0],
            [0, 2, 1, 3],
            [3, 1, 0, 2]
        ]
        self.S1 = S1 if S1 is not None else [
            [0, 1, 2, 3],
            [2, 3, 1, 0],
            [3, 0, 1, 2],
            [2, 1, 0, 3]
        ]
        self.P4 = P4 if P4 is not None else [2, 4, 3, 1]
        self.k1, self.k2 = self.key_generation()

    def permute(self, block, table):
        '''按照给定的表进行排列操作'''
        return ''.join([block[x - 1] for x in table])

    def left_shift(self, block, shifts):
        '''将给定的block进行循环左移操作'''
        return block[shifts:] + block[:shifts]

    def key_generation(self):
        '''密钥生成函数'''
        after_p10 = self.permute(self.key, self.P10)
        left, right = after_p10[:5], after_p10[5:]
        ls1_left, ls1_right = self.left_shift(left, 1), self.left_shift(right, 1)
        ls2_left, ls2_right = self.left_shift(ls1_left, 1), self.left_shift(ls1_right, 1)
        k1 = self.permute(ls1_left + ls1_right, self.P8)
        k2 = self.permute(ls2_left + ls2_right, self.P8)
        return k1, k2

    def f(self, right, subkey):
        '''轮函数f，负责进行扩展、置换、S盒转换等操作'''
        after_ep = self.permute(right, self.EP)
        after_xor = bin(int(after_ep, 2) ^ int(subkey, 2))[2:].zfill(8)
        left_xor, right_xor = after_xor[:4], after_xor[4:]
        left_s0_row = int(left_xor[0] + left_xor[3], 2)
        left_s0_col = int(left_xor[1] + left_xor[2], 2)
        right_s1_row = int(right_xor[0] + right_xor[3], 2)
        right_s1_col = int(right_xor[1] + right_xor[2], 2)
        sbox_left = bin(self.S0[left_s0_row][left_s0_col])[2:].zfill(2)
        sbox_right = bin(self.S1[right_s1_row][right_s1_col])[2:].zfill(2)
        after_p4 = self.permute(sbox_left + sbox_right, self.P4)
        return after_p4

    def encrypt(self, plaintext):
        '''加密函数，输入明文，输出密文'''
        binary_blocks = [self.ascii_to_binary(char) for char in plaintext]
        encrypted_blocks = [self.encrypt_block(block) for block in binary_blocks]
        return ''.join(encrypted_blocks)

    def decrypt(self, ciphertext):
        '''解密函数，输入密文，输出明文'''
        binary_blocks = [self.ascii_to_binary(char) for char in ciphertext]
        decrypted_blocks = [self.decrypt_block(block) for block in binary_blocks]
        return ''.join(decrypted_blocks)

    def encrypt_block(self, block):
        '''加密单个块'''
        after_ip = self.permute(block, self.IP)
        left, right = after_ip[:4], after_ip[4:]
        left, right = right, bin(int(left, 2) ^ int(self.f(right, self.k1), 2))[2:].zfill(4)
        left = bin(int(left, 2) ^ int(self.f(right, self.k2), 2))[2:].zfill(4)
        ciphertext = self.permute(left + right, self.IP_INV)
        return self.binary_to_ascii(ciphertext)

    def decrypt_block(self, block):
        '''解密单个块'''
        after_ip = self.permute(block, self.IP)
        left, right = after_ip[:4], after_ip[4:]
        left, right = right, bin(int(left, 2) ^ int(self.f(right, self.k2), 2))[2:].zfill(4)
        left = bin(int(left, 2) ^ int(self.f(right, self.k1), 2))[2:].zfill(4)
        plaintext = self.permute(left + right, self.IP_INV)
        return self.binary_to_ascii(plaintext)

    def ascii_to_binary(self, text):
        '''将ASCII字符串转换为二进制字符串'''
        return ''.join(bin(ord(char))[2:].zfill(8) for char in text)

    def binary_to_ascii(self, binary):
        '''将二进制字符串转换为ASCII字符串'''
        return ''.join(chr(int(binary[i:i + 8], 2)) for i in range(0, len(binary), 8))

