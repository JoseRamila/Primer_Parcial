import hashlib
from PyPDF2 import PdfReader, PdfWriter
import Crypto.Util.number
from Crypto.Util import number
import io

#Número de bits
bits = 1024

#Obtener los primos para Alice y Bob
pA = Crypto.Util.number.getPrime(bits, randfunc= Crypto.Random.get_random_bytes)
qA = Crypto.Util.number.getPrime(bits, randfunc= Crypto.Random.get_random_bytes)


pB = Crypto.Util.number.getPrime(bits, randfunc= Crypto.Random.get_random_bytes)
qB = Crypto.Util.number.getPrime(bits, randfunc= Crypto.Random.get_random_bytes)


#Obtener la primera parte de la llave pública de Alice y Bob
nA = pA * qA
nB = pB * qB


#Calculamos el indicador de Euer Phi
phiA = (pA - 1)*(qA - 1)
phiB = (pB - 1)*(qB - 1)


#Por razones de eficiencia usaremos el número 4 de Fermat, 65537, debido a que es un primo largo y no tiene potencia de 2 y como forma parte
# de la clave pública no es necesario calcularlo 

Fermat = 65537

#Calcular la llave privada de Alice y Bob
dA = Crypto.Util.number.inverse(Fermat, phiA)
dB = Crypto.Util.number.inverse(Fermat, phiB)


# Función para generar claves RSA
def generate_rsa_keys(bits=1024):
    p = number.getPrime(bits)
    q = number.getPrime(bits)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537  # Número de Fermat
    d = number.inverse(e, phi)
    return ((e, n), (d, n))

# Función para firmar un mensaje usando RSA
def sign_message(message, private_key):
    d, n = private_key
    hashed_message = hashlib.sha256(message.encode()).digest()
    signature = pow(int.from_bytes(hashed_message, byteorder='big'), d, n)
    return signature

# Función para verificar una firma usando RSA
def verify_signature(message, signature, public_key):
    e, n = public_key
    hashed_message = hashlib.sha256(message.encode()).digest()
    hashed_message_int = int.from_bytes(hashed_message, byteorder='big')
    decrypted_signature = pow(signature, e, n)
    return hashed_message_int == decrypted_signature

# Generar claves RSA para Alice y la Autoridad Certificadora (AC)
alice_public_key, alice_private_key = generate_rsa_keys()
ac_public_key, ac_private_key = generate_rsa_keys()

# Leer el contenido del archivo PDF
pdf_file_path = "NDA.pdf"
with open(pdf_file_path, 'rb') as file:
    pdf_content = file.read()

# Crear un objeto BytesIO a partir del contenido del archivo PDF
pdf_stream = io.BytesIO(pdf_content)

# Calcular el hash SHA-256 del contenido del archivo PDF
hash_pdf = hashlib.sha256(pdf_content)
hex_digest = hash_pdf.hexdigest()

# Firmar el hash con la clave privada de Alice
signature_A = pow(int(hex_digest, 16), dA, nA)

# Agregar la firma de Alice al archivo PDF
pdf_writer = PdfWriter()
pdf_writer.add_attachment('alice_signature.txt', str(signature_A).encode())
pdf_reader = PdfReader(pdf_stream)
pdf_writer.add_page(pdf_reader.pages[0])  # Agregar la primera página del PDF original

# Guardar el PDF con la firma de Alice
signed_pdf_path = "NDA_signed_by_Alice.pdf"
with open(signed_pdf_path, 'wb') as file:
    pdf_writer.write(file)


# Verificar la firma de Alice por la AC usando la clave pública de Alice
is_signature_valid_A = pow(signature_A, Fermat, nA) == int(hex_digest, 16)


if is_signature_valid_A:
    print("\n","La Autoridad Certificadora (AC) ha verificado la firma de Alice.","\n")
else:
    print("\n","La firma de Alice no es válida para la Autoridad Certificadora (AC).","\n")


# Firmar el PDF con la clave privada de la AC
signature_B = pow(int(hex_digest, 16), dB, nB)

# Agregar la firma de la AC al archivo PDF
pdf_writer.add_attachment('ac_signature.txt', str(signature_B).encode())

# Guardar el PDF con la firma de la AC
ac_signed_pdf_path = "NDA_signed_by_AC.pdf"
with open(ac_signed_pdf_path, 'wb') as file:
    pdf_writer.write(file)

# Verificar la firma de la AC por Bob usando la clave pública de la AC
is_signature_valid_B = pow(signature_B, Fermat, nB) == int(hex_digest, 16)

if is_signature_valid_B:
    print("\n","Bob ha verificado la firma de la Autoridad Certificadora (AC).","\n")
else:
    print("\n","La firma de la Autoridad Certificadora (AC) no es válida para Bob.","\n")