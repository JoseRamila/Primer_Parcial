import hashlib
import random

# Función para dividir el mensaje en partes más pequeñas de 128 caracteres
def divide_message(message):
    return [message[i:i+128] for i in range(0, len(message), 128)]

# Función para calcular el hash SHA-256 de un mensaje
def calculate_hash(message):
    return hashlib.sha256(message.encode()).hexdigest()

# Función para elevar a la potencia módulo n (exponenciación modular)
def pow_mod(base, exponent, modulus):
    result = 1
    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        exponent //= 2
        base = (base * base) % modulus
    return result

# Función para generar un número primo grande
def generate_prime():
    while True:
        # Generar un número aleatorio grande
        prime_candidate = random.randint(2**1023, 2**1024 - 1)
        
        # Verificar si el número es primo
        if is_prime(prime_candidate):
            return prime_candidate

# Función para verificar si un número es primo
def is_prime(n, k=5):
    if n <= 1:
        return False
    elif n <= 3:
        return True
    elif n % 2 == 0:
        return False

    # Escribir n - 1 como 2^r * d
    r = 0
    d = n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Realizar el test de Miller-Rabin
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

# Función para generar claves RSA
def generate_keypair():
    # Seleccionar dos números primos grandes p y q
    p = generate_prime()
    q = generate_prime()

    # Calcular n y phi(n)
    n = p * q
    phi = (p - 1) * (q - 1)

    # Fijar el exponente de cifrado e
    e = 65537

    # Calcular el exponente de descifrado d
    d = mod_inverse(e, phi)

    return ((e, n), (d, n))

# Función para cifrar un mensaje
def encrypt(public_key, plaintext):
    e, n = public_key
    cipher = [pow_mod(ord(char), e, n) for char in plaintext]
    return cipher

# Función para descifrar un mensaje
def decrypt(private_key, cipher):
    d, n = private_key
    plain = [chr(pow_mod(char, d, n)) for char in cipher]
    return ''.join(plain)

# Función para calcular el máximo común divisor
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

# Función para calcular el inverso modular
def mod_inverse(a, m):
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise Exception('No existe el inverso modular')
    else:
        return x % m

# Función para calcular el algoritmo extendido de Euclides
def extended_gcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        gcd, x, y = extended_gcd(b % a, a)
        return (gcd, y - (b // a) * x, x)

# Mensaje original
message = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Duis pharetra arcu sit amet arcu dictum, ac pretium sem porta. Cras id risus augue. Donec a pellentesque eros, at pretium ipsum. Suspendisse potenti. Praesent vestibulum sodales magna sit amet efficitur. Sed feugiat odio aliquam nisi dapibus, sed ullamcorper sem facilisis. Donec felis justo, malesuada in ante quis, vestibulum hendrerit dolor. Nulla a consectetur lorem. Praesent mattis vel eros ac suscipit. Duis in facilisis magna. Nam id ipsum magna. Integer leo tortor, ultricies ac leo id, laoreet pretium est. Praesent tincidunt sed magna eget commodo. Praesent vitae augue et quam interdum mattis nec vitae enim. Donec quis placerat nisi. Vivamus cursus tellus arcu, a tincidunt odio cursus in. Maecenas sit amet finibus risus. Ut id dolor pretium, luctus mi eu, congue ante. Nunc malesuada metus nec eleifend condimentum. Morbi ornare quam nunc, vel consequat metus congue at. Mauris sit amet sollicitudin tellus. Praesent at erat mi. Phasellus tincidunt, nulla sed congue turpis duis."
# Dividir el mensaje en partes más pequeñas
message_parts = divide_message(message)

# Generar claves RSA
public_key, private_key = generate_keypair()

# Cifrar cada parte con la llave pública
cipher_texts = []
i = 1
for part in message_parts:
    cipher_text = encrypt(public_key, part)
    cipher_texts.append(cipher_text)
    print("Mensaje en partes: ", i)
    i += 1
    

# Descifrar los mensajes con la llave privada
decrypted_message = ''
for cipher_text in cipher_texts:
    decrypted_part = decrypt(private_key, cipher_text)
    decrypted_message += decrypted_part

# Calcular el hash del mensaje original
original_hash = calculate_hash(message)

# Calcular el hash del mensaje descifrado
received_hash = calculate_hash(decrypted_message)

# Comparar los hashes
if original_hash == received_hash:
    print("Los hashes coinciden. El mensaje es auténtico.")
else:
    print("Los hashes no coinciden. El mensaje podría haber sido alterado.")

