import socket
import pickle
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

def main():
    # Configurar o socket do servidor
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('localhost', 12345)  # Altere conforme necessário
    server_socket.bind(server_address)
    server_socket.listen(1)

    print("Aguardando conexão da Máquina Virtual 1...")
    client_socket, client_address = server_socket.accept()
    print(f"Conexão estabelecida com {client_address}")

    # Receber mensagem da Máquina Virtual 1
    received_message = client_socket.recv(4096).decode()
    print("Mensagem recebida da Máquina Virtual 1:", received_message)

    # Encriptar mensagem usando RSA
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    public_key = private_key.public_key()

    encrypted_message = public_key.encrypt(
        received_message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    print(f'Mensagem encriptada {encrypted_message}\n\n')
    # Serializar a mensagem encriptada e a chave privada antes de enviá-las
    serialized_data = pickle.dumps((encrypted_message, private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )))

    client_socket.sendall(serialized_data)
    print(f'Mensagem serializada: {serialized_data}\n\n')
    # Fechar o socket do servidor
    server_socket.close()

if __name__ == "__main__":
    main()