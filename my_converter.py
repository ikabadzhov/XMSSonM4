import os
import re
import numpy as np
import matplotlib.pyplot as plt
import sys



if len(sys.argv) != 2: 
    SPEED_PATH = './benchmarks_F1/speed/crypto_sign/xmss/ref'
    HASH_PATH = './benchmarks_F1/hashing/crypto_sign/xmss/ref'
    SIZE_PATH = './benchmarks_F1/size/crypto_sign/xmss/ref'
    STACK_PATH = './benchmarks_F1/stack/crypto_sign/xmss/ref'
else:  # provide a benchmarking folder
    SPEED_PATH = './'+str(sys.argv[1])+'/speed/crypto_sign/xmss/ref'
    HASH_PATH = './'+str(sys.argv[1])+'/hashing/crypto_sign/xmss/ref'
    SIZE_PATH = './'+str(sys.argv[1])+'/size/crypto_sign/xmss/ref'
    STACK_PATH = './'+str(sys.argv[1])+'/stack/crypto_sign/xmss/ref'




def speed_converter():
    if not os.path.exists(SPEED_PATH):
        return
    file_paths = list(map(lambda x: SPEED_PATH+'/'+x, sorted(os.listdir(SPEED_PATH))))
    speed_data = [open(f, 'r') for f in file_paths]
    speed_data = [g.read() for g in speed_data]

    sn = '\nsign cycles: \n'
    vr = '\nverify cycles: \n'

    KP_list = np.zeros(len(speed_data))
    SN_list = np.zeros(len(speed_data))
    VR_cycles = np.zeros(len(speed_data))
    VR_list = np.zeros(len(speed_data))

    for i in np.arange(len(speed_data)):
        KP_list[i] = float(speed_data[i][speed_data[i].find('\n')+len('\n'):speed_data[i].rfind(sn)])/(24*np.power(10, 6))
        SN_list[i] = float(speed_data[i][speed_data[i].find(sn)+len(sn):speed_data[i].rfind(vr)])/(24*np.power(10, 6))
        VR_list[i] = float(speed_data[i][speed_data[i].find(vr)+len(vr):-1])/(24*np.power(10, 6))
        VR_cycles[i] = int(speed_data[i][speed_data[i].find(vr)+len(vr):-1])

    return KP_list, SN_list, VR_list, VR_cycles




def hash_converter():
    if not os.path.exists(HASH_PATH):
        return
    file_paths = list(map(lambda x: HASH_PATH+'/'+x, sorted(os.listdir(HASH_PATH))))
    hash_data = [open(f, 'r') for f in file_paths]
    hash_data = [g.read() for g in hash_data]

    s1 = '\nkeypair hash cycles:\n'
    s2 = '\nsign cycles: \n'
    s3 = '\nsign hash cycles: \n'
    s4 = '\nverify cycles: \n'
    s5 = '\nverify hash cycles: \n'

    keypair_cycles = np.zeros(len(hash_data))
    keypair_hash_cycles = np.zeros(len(hash_data))
    sign_cycles = np.zeros(len(hash_data))
    sign_hash_cycles = np.zeros(len(hash_data))
    verify_cycles = np.zeros(len(hash_data))
    verify_hash_cycles = np.zeros(len(hash_data))

    for i in np.arange(len(hash_data)):
        keypair_cycles[i] = float(hash_data[i][hash_data[i].find('\n')+len('\n'):hash_data[i].rfind(s1)])/(24*np.power(10, 6))
        keypair_hash_cycles[i] = float(hash_data[i][hash_data[i].find(s1)+len(s1):hash_data[i].rfind(s2)])/(24*np.power(10, 6))
        sign_cycles[i] = float(hash_data[i][hash_data[i].find(s2)+len(s2):hash_data[i].rfind(s3)])/(24*np.power(10, 6))
        sign_hash_cycles[i] = float(hash_data[i][hash_data[i].find(s3)+len(s3):hash_data[i].rfind(s4)])/(24*np.power(10, 6))
        verify_cycles[i] = float(hash_data[i][hash_data[i].find(s4)+len(s4):hash_data[i].rfind(s5)])/(24*np.power(10, 6))
        verify_hash_cycles[i] = float(hash_data[i][hash_data[i].find(s5)+len(s5):-1])/(24*np.power(10, 6))

    return keypair_cycles, keypair_hash_cycles, sign_cycles, sign_hash_cycles, verify_cycles, verify_hash_cycles




def size_converter():
    if not os.path.exists(SIZE_PATH):
        return
    file_paths = list(map(lambda x: SIZE_PATH+'/'+x, sorted(os.listdir(SIZE_PATH))))
    size_data = [open(f, 'r') for f in file_paths]
    size_data = [g.read() for g in size_data]

    s1 = '\n.data bytes:\n'
    s2 = '\n.bss bytes:\n'
    s3 = '\n.total bytes:\n'

    txt = np.zeros(len(size_data))
    dat = np.zeros(len(size_data))
    bss = np.zeros(len(size_data))
    total = np.zeros(len(size_data))

    for i in np.arange(len(size_data)):
        txt[i] = int(size_data[i][size_data[i].find('\n')+len('\n'):size_data[i].rfind(s1)])
        dat[i] = int(size_data[i][size_data[i].find(s1)+len(s1):size_data[i].rfind(s2)])
        bss[i] = int(size_data[i][size_data[i].find(s2)+len(s2):size_data[i].rfind(s3)])
        total[i] = int(size_data[i][size_data[i].find(s3)+len(s3):-1])

    return txt, dat, bss, total


def stack_converter():
    if not os.path.exists(STACK_PATH):
        return
    file_paths = list(map(lambda x: STACK_PATH+'/'+x, sorted(os.listdir(STACK_PATH))))
    stack_data = [open(f, 'r') for f in file_paths]
    stack_data = [g.read() for g in stack_data]

    s1 = '\ncrypto_sign stack usage\n'
    s2 = '\ncrypto_sign_open stack usage\n'
    s3 = '\nSignature valid!'

    crypto_sign_keypair = np.zeros(len(stack_data))
    crypto_sign = np.zeros(len(stack_data))
    crypto_sign_open = np.zeros(len(stack_data))

    for i in np.arange(len(stack_data)):
        crypto_sign_keypair[i] = int(stack_data[i][stack_data[i].find('\n')+len('\n'):stack_data[i].rfind(s1)])
        crypto_sign[i] = int(stack_data[i][stack_data[i].find(s1)+len(s1):stack_data[i].rfind(s2)])
        crypto_sign_open[i] = int(stack_data[i][stack_data[i].find(s2)+len(s2):stack_data[i].rfind(s3)])

    return crypto_sign_keypair, crypto_sign, crypto_sign_open



KP, SN, VR, VRC = speed_converter()
keypair_c, keypair_hash_c, sign_c, sign_hash_c, verify_c, verify_hash_c = hash_converter()
TXT, DAT, BSS, TOTAL = size_converter()
KP_stack, SN_stack, VR_stack = stack_converter()
VRC = VRC.astype(int)

a = " & "
l = "\\\\\n\\hline"

print()
print("\\begin{table}[ht]\n\\caption{Time Performance of XMSS for different heights}")
print("\\begin{tabular}{ | c  | c  | c | c | c |}\\hline")
print("height &  Key Gen. (s) & Sign. Gen. (s) & Sign. Ver. (s) & Sign. Gen. $+$ Sign. Ver. (s)"+l)
print("10 & "+str(round(KP[0], 4))+a+str(round(SN[0], 4))+a+str(round(VR[0], 4))+a+str(round(SN[0]+VR[0], 4))+l)
print("16 & "+str(round(KP[4], 4))+a+str(round(SN[4], 4))+a+str(round(VR[4], 4))+a+str(round(SN[4]+VR[4], 4))+l)
print("20 & "+str(round(KP[8], 4))+a+str(round(SN[8], 4))+a+str(round(VR[8], 4))+a+str(round(SN[8]+VR[8], 4))+l)
print("\\end{tabular}\n\\end{table}")


print()
print("\\begin{table}[ht]\n\\caption{Time Performance of XMSS for $h=10$ improvements}")
print("\\begin{tabular}{ | c  | c  | c | c | c |}\\hline")
print("Flags &  Key Gen. (s) & Sign. Gen. (s) & Sign. Ver. (s) & SG $+$ SV"+l)
print("none & "+str(round(KP[0], 4))+a+str(round(SN[0], 4))+a+str(round(VR[0], 4))+a+str(round(SN[0]+VR[0], 4))+l)
print("NO\\_BITMASK & "+str(round(KP[1], 4))+a+str(round(SN[1], 4))+a+str(round(VR[1], 4))+a+str(round(SN[1]+VR[1], 4))+l)
print("PRE\\_COMP & "+str(round(KP[2], 4))+a+str(round(SN[2], 4))+a+str(round(VR[2], 4))+a+str(round(SN[2]+VR[2], 4))+l)
print("both & "+str(round(KP[3], 4))+a+str(round(SN[3], 4))+a+str(round(VR[3], 4))+a+str(round(SN[3]+VR[3], 4))+l)
print("\\end{tabular}\n\\end{table}")




print()
print("\\begin{table}[ht]\n\\caption{Time Performance of XMSS for $h=16$ improvements}")
print("\\begin{tabular}{ | c  | c  | c | c | c |}\\hline")
print("Flags &  Key Gen. (s) & Sign. Gen. (s) & Sign. Ver. (s) & SG $+$ SV"+l)
print("none & "+str(round(KP[4], 4))+a+str(round(SN[4], 4))+a+str(round(VR[4], 4))+a+str(round(SN[4]+VR[4], 4))+l)
print("NO\\_BITMASK & "+str(round(KP[5], 4))+a+str(round(SN[5], 4))+a+str(round(VR[5], 4))+a+str(round(SN[5]+VR[5], 4))+l)
print("PRE\\_COMP & "+str(round(KP[6], 4))+a+str(round(SN[6], 4))+a+str(round(VR[6], 4))+a+str(round(SN[6]+VR[6], 4))+l)
print("both & "+str(round(KP[7], 4))+a+str(round(SN[7], 4))+a+str(round(VR[7], 4))+a+str(round(SN[7]+VR[7], 4))+l)
print("\\end{tabular}\n\\end{table}")

print()
print("\\begin{table}[ht]\n\\caption{Time Performance of XMSS for $h=20$ improvements}")
print("\\begin{tabular}{ | c  | c  | c | c | c |}\\hline")
print("Flags &  Key Gen. (s) & Sign. Gen. (s) & Sign. Ver. (s) & SG $+$ SV"+l)
print("none & "+str(round(KP[8], 4))+a+str(round(SN[8], 4))+a+str(round(VR[8], 4))+a+str(round(SN[8]+VR[8], 4))+l)
print("NO\\_BITMASK & "+str(round(KP[9], 4))+a+str(round(SN[9], 4))+a+str(round(VR[9], 4))+a+str(round(SN[9]+VR[9], 4))+l)
print("PRE\\_COMP & "+str(round(KP[10], 4))+a+str(round(SN[10], 4))+a+str(round(VR[10], 4))+a+str(round(SN[10]+VR[10], 4))+l)
print("both & "+str(round(KP[11], 4))+a+str(round(SN[11], 4))+a+str(round(VR[11], 4))+a+str(round(SN[11]+VR[11], 4))+l)
print("\\end{tabular}\n\\end{table}")


print()
print("\\begin{longtable}{ | c | c  | c  | c | c | c | c | c | } \\caption{All time results of XMSS Signature Verification} \\hline")
print("No. & $h$ & NO\\_BITMASK & PRE\\_COMP & SHIFT & BLOCK & Ver. in s & Ver. in cycles"+l)
for ind, h in enumerate([10, 16, 20]):
    print(str(4*ind)+a+str(h)+a+'0'+a+'0'+a+'N/A'+a+'N/A'+a+str(round(VR[4*ind], 4))+a+str(VRC[4*ind])+l)
    print(str(4*ind+1)+a+str(h)+a+'1'+a+'0'+a+'N/A'+a+'N/A'+a+str(round(VR[4*ind+1], 4))+a+str(VRC[4*ind+1])+l)
    print(str(4*ind+2)+a+str(h)+a+'0'+a+'1'+a+'N/A'+a+'N/A'+a+str(round(VR[4*ind+2], 4))+a+str(VRC[4*ind+2])+l)
    print(str(4*ind+3)+a+str(h)+a+'1'+a+'1'+a+'N/A'+a+'N/A'+a+str(round(VR[4*ind+3], 4))+a+str(VRC[4*ind+3])+l)
ind2 = 12  # easier to create an index on this level    
for b in [0, 1, 2]:
    for s in np.arange(8, 16):
        for h in [10, 16, 20]:
            print(str(ind2)+a+str(h)+a+'0'+a+'0'+a+str(s)+a+str(b)+a+str(round(VR[ind2], 4))+a+str(VRC[ind2])+l)
            print(str(ind2+1)+a+str(h)+a+'1'+a+'0'+a+str(s)+a+str(b)+a+str(round(VR[ind2+1], 4))+a+str(VRC[ind2+1])+l)
            print(str(ind2+2)+a+str(h)+a+'0'+a+'1'+a+str(s)+a+str(b)+a+str(round(VR[ind2+2], 4))+a+str(VRC[ind2+2])+l)
            print(str(ind2+3)+a+str(h)+a+'1'+a+'1'+a+str(s)+a+str(b)+a+str(round(VR[ind2+3], 4))+a+str(VRC[ind2+3])+l)
            ind2 += 4
print("\\end{longtable}")


T = np.arange(8, 16)

#print(min(VR[12:108:12]), min(VRC[12:108:12]))
#print(min(VR[12+3:108:12]), min(VRC[12+3:108:12]))


fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2)
fig.set_figheight(6)
fig.set_figwidth(10)

ax1.grid()
ax1.set_title('no additional flags')
ax1.plot(T, VR[12:108:12], marker='o', linewidth=0.5, label="BLOCK=0")
ax1.plot(T, VR[108:204:12], marker='o', linewidth=0.5, label="BLOCK=1")
ax1.plot(T, VR[204::12], marker='o', linewidth=0.5, label="BLOCK=2")
ax1.set_xlabel('$T$')
ax1.set_ylabel('time in seconds')
ax1.legend()

ax2.grid()
ax2.set_title('NO_BITMASK')
ax2.plot(T, VR[12+1:108:12], marker='o', linewidth=0.5, label="BLOCK=0")
ax2.plot(T, VR[108+1:204:12], marker='o', linewidth=0.5, label="BLOCK=1")
ax2.plot(T, VR[204+1::12], marker='o', linewidth=0.5, label="BLOCK=2")
ax2.set_xlabel('$T$')
ax2.set_ylabel('time in seconds')
ax2.legend()


ax3.grid()
ax3.set_title('PRE_COMP')
ax3.plot(T, VR[12+2:108:12], marker='o', linewidth=0.5, label="BLOCK=0")
ax3.plot(T, VR[108+2:204:12], marker='o', linewidth=0.5, label="BLOCK=1")
ax3.plot(T, VR[204+2::12], marker='o', linewidth=0.5, label="BLOCK=2")
ax3.set_xlabel('$T$')
ax3.set_ylabel('time in seconds')
ax3.legend()

ax4.grid()
ax4.set_title('both')
ax4.plot(T, VR[12+3:108:12], marker='o', linewidth=0.5, label="BLOCK=0")
ax4.plot(T, VR[108+3:204:12], marker='o', linewidth=0.5, label="BLOCK=1")
ax4.plot(T, VR[204+3::12], marker='o', linewidth=0.5, label="BLOCK=2")
ax4.set_xlabel('$T$')
ax4.set_ylabel('time in seconds')
ax4.legend()

fig.tight_layout()
fig.show()
#fig.savefig('h10r.png')

'''
print(min(VR[12+4:108:12]), min(VRC[12+4:108:12]))
print(VR[12+4:108:12])
print(min(VR[108+4:204:12]), min(VRC[108+4:204:12]))
print(min(VR[204+4::12]), min(VRC[204+4::12]))

print(min(VR[12+4+1:108:12]), min(VRC[12+4+1:108:12]))
print(VR[12+4+1:108:12])
print(min(VR[108+4+1:204:12]), min(VRC[108+4+1:204:12]))
print(min(VR[204+4+1::12]), min(VRC[204+4+1::12]))

print(min(VR[12+4+2:108:12]), min(VRC[12+4+2:108:12]))
print(min(VR[108+4+2:204:12]), min(VRC[108+4+2:204:12]))
print(min(VR[204+4+2::12]), min(VRC[204+4+2::12]))

print(min(VR[12+4+3:108:12]), min(VRC[12+4+3:108:12]))
print(min(VR[108+4+3:204:12]), min(VRC[108+4+3:204:12]))
print(min(VR[204+4+3::12]), min(VRC[204+4+3::12]))

print()
print(min(VR[12+8:108:12]), min(VRC[12+8:108:12]))
print(min(VR[108+8:204:12]), min(VRC[108+8:204:12]))
print(min(VR[204+8::12]), min(VRC[204+8::12]))
print(VR[204+8::12])

print(min(VR[12+8+1:108:12]), min(VRC[12+8+1:108:12]))
print(min(VR[108+8+1:204:12]), min(VRC[108+8+1:204:12]))
print(min(VR[204+8+1::12]), min(VRC[204+8+1::12]))

print(min(VR[12+8+2:108:12]), min(VRC[12+8+2:108:12]))
print(min(VR[108+8+2:204:12]), min(VRC[108+8+2:204:12]))
print(min(VR[204+8+2::12]), min(VRC[204+8+2::12]))

print(min(VR[12+8+3:108:12]), min(VRC[12+8+3:108:12]))
print(VR[12+8+3:108:12])
print(min(VR[108+8+3:204:12]), min(VRC[108+8+3:204:12]))
print(min(VR[204+8+3::12]), min(VRC[204+8+3::12]))
'''


print()
print("\\begin{table}[ht]\n\\caption{Rapid Signature Verification of XMSS for different heights}")
print("\\begin{tabular}{ | c  | c  | c | c | c |}\\hline")
print("Shift &  Block Size & $h=10$ & $h=16$ & $h=20$"+l)
print("N/A & N/A & "+str(round(VR[0], 4))+a+str(round(VR[4], 4))+a+str(round(VR[8], 4))+l)
for ind in np.arange(8):
    print(str(ind+8)+a+'0'+a+str(round(VR[12+12*ind], 4))+a+str(round(VR[16+12*ind], 4))+a+str(round(VR[20+12*ind], 4))+l)
for ind in np.arange(8):
    print(str(ind+8)+a+'1'+a+str(round(VR[108+12*ind], 4))+a+str(round(VR[108+12*ind], 4))+a+str(round(VR[108+12*ind], 4))+l)
for ind in np.arange(8):
    print(str(ind+8)+a+'2'+a+str(round(VR[204+12*ind], 4))+a+str(round(VR[204+12*ind], 4))+a+str(round(VR[204+12*ind], 4))+l)
print("\\end{tabular}\n\\end{table}")

print()
print("\\begin{table}[ht]\n\\caption{Rapid Signature Verification of XMSS for different heights}")
print("\\begin{tabular}{ | c  | c  | c | c | c |}\\hline")
print("Shift &  Block Size & $h=10$ & $h=16$ & $h=20$"+l)
print("N/A & N/A & "+str(round(VR[0], 4))+a+str(round(VR[4], 4))+a+str(round(VR[8], 4))+l)
for ind in np.arange(8):
    print(str(ind+8)+a+'0'+a+str(round(VR[12+1+12*ind], 4))+a+str(round(VR[16+1+12*ind], 4))+a+str(round(VR[20+1+12*ind], 4))+l)
for ind in np.arange(8):
    print(str(ind+8)+a+'1'+a+str(round(VR[108+1+12*ind], 4))+a+str(round(VR[108+1+12*ind], 4))+a+str(round(VR[108+1+12*ind], 4))+l)
for ind in np.arange(8):
    print(str(ind+8)+a+'2'+a+str(round(VR[204+1+12*ind], 4))+a+str(round(VR[204+1+12*ind], 4))+a+str(round(VR[204+1+12*ind], 4))+l)
print("\\end{tabular}\n\\end{table}")

print()
print("\\begin{table}[ht]\n\\caption{Rapid Signature Verification of XMSS for different heights}")
print("\\begin{tabular}{ | c  | c  | c | c | c |}\\hline")
print("Shift &  Block Size & $h=10$ & $h=16$ & $h=20$"+l)
print("N/A & N/A & "+str(round(VR[0], 4))+a+str(round(VR[4], 4))+a+str(round(VR[8], 4))+l)
for ind in np.arange(8):
    print(str(ind+8)+a+'0'+a+str(round(VR[12+2+12*ind], 4))+a+str(round(VR[16+2+12*ind], 4))+a+str(round(VR[20+2+12*ind], 4))+l)
for ind in np.arange(8):
    print(str(ind+8)+a+'1'+a+str(round(VR[108+2+12*ind], 4))+a+str(round(VR[108+2+12*ind], 4))+a+str(round(VR[108+2+12*ind], 4))+l)
for ind in np.arange(8):
    print(str(ind+8)+a+'2'+a+str(round(VR[204+2+12*ind], 4))+a+str(round(VR[204+2+12*ind], 4))+a+str(round(VR[204+2+12*ind], 4))+l)
print("\\end{tabular}\n\\end{table}")

print()
print("\\begin{table}[ht]\n\\caption{Rapid Signature Verification of XMSS for different heights}")
print("\\begin{tabular}{ | c  | c  | c | c | c |}\\hline")
print("Shift &  Block Size & $h=10$ & $h=16$ & $h=20$"+l)
print("N/A & N/A & "+str(round(VR[0], 4))+a+str(round(VR[4], 4))+a+str(round(VR[8], 4))+l)
for ind in np.arange(8):
    print(str(ind+8)+a+'0'+a+str(round(VR[12+3+12*ind], 4))+a+str(round(VR[16+3+12*ind], 4))+a+str(round(VR[20+3+12*ind], 4))+l)
for ind in np.arange(8):
    print(str(ind+8)+a+'1'+a+str(round(VR[108+3+12*ind], 4))+a+str(round(VR[108+3+12*ind], 4))+a+str(round(VR[108+3+12*ind], 4))+l)
for ind in np.arange(8):
    print(str(ind+8)+a+'2'+a+str(round(VR[204+3+12*ind], 4))+a+str(round(VR[204+3+12*ind], 4))+a+str(round(VR[204+3+12*ind], 4))+l)
print("\\end{tabular}\n\\end{table}")





# for the presentation
'''
t = np.arange(8, 16)

plt.figure()
plt.title("Signature Generation")
plt.grid()
plt.plot(t, SN[1:12*8+1:12], marker='o', linewidth='0.5', label='$h=10$')
plt.plot(t, SN[4+1:12*8+1+4:12], marker='o', linewidth='0.5', label='$h=16$')
plt.plot(t, SN[8+1:12*8+1+8:12], marker='o', linewidth='0.5', label='$h=20$')
plt.xlabel('$T$')
plt.ylabel('time in seconds')
plt.legend()
plt.show()
#plt.savefig('1.png')

plt.figure()
plt.title("Signature Verification")
plt.grid()
plt.plot(t, VR[1:12*8+1:12], marker='o', linewidth='0.5', label='$h=10$')
plt.plot(t, VR[4+1:12*8+1+4:12], marker='o', linewidth='0.5', label='$h=16$')
plt.plot(t, VR[8+1:12*8+1+8:12], marker='o', linewidth='0.5', label='$h=20$')
plt.xlabel('$T$')
plt.ylabel('time in seconds')
plt.legend()
plt.show()
#plt.savefig('2.png')

plt.figure()
plt.title("Signature Verification")
plt.grid()
plt.plot(VR)
#plt.plot(t, VR[4+1:12*8+1+4:12], marker='o', linewidth='0.5', label='$h=16$')
#plt.plot(t, VR[8+1:12*8+1+8:12], marker='o', linewidth='0.5', label='$h=20$')
plt.xlabel('$T$')
plt.ylabel('time in seconds')
plt.legend()
plt.show()
'''
