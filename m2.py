import socket
import pickle
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

def main():
    # Configura o socket do servidor
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('localhost', 12345) 
    server_socket.bind(server_address)
    server_socket.listen(1)

    print("Aguardando conexão da Máquina Virtual 1...")
    client_socket, client_address = server_socket.accept()
    print(f"Conexão estabelecida com {client_address}")

    # Recebe mensagem da Máquina Virtual 1
    received_message = client_socket.recv(4096).decode()
    print("Mensagem recebida da Máquina Virtual 1:", received_message)

    # Encripta mensagem usando RSA
    private_key = rsa.generate_private_key( # gerar uma chave privada RSA
        public_exponent=65537,              # com um expoente público de 65537
        key_size=2048,                      # e um tamanho de chave de 2048 bits,
        backend=default_backend()           # utilizando o backend padrão
    )

    public_key = private_key.public_key()

    encrypted_message = public_key.encrypt( #criptografa usando chave publica
        received_message.encode(),          #codifica para bytes
        padding.OAEP(                       #OEAP -> esquema de preenchimento p o rsa assimétrico
            mgf=padding.MGF1(algorithm=hashes.SHA256()), # método de geração de mascara é o MGF1
            algorithm=hashes.SHA256(),                   # c o algoritmo de hash SHA256
            label=None
        )
    )

    print(f'Bytes da Mensagem encriptada:\n {encrypted_message}\n\n')
    # Serializa a mensagem encriptada e a chave privada antes de enviá-las
    serialized_data = pickle.dumps((encrypted_message, private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )))

    client_socket.sendall(serialized_data)
    print(f'Bytes da Mensagem encriptada serializada:\n {serialized_data}\n\n')
    # Fecha o socket do servidor
    server_socket.close()

if __name__ == "__main__":
    main()
