import time
import socket
import pickle
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

def main():
    # Configura o socket do cliente
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('localhost', 12345)  

    try:
        # Tenta conectar ao servidor
        client_socket.connect(server_address)

        # Envia mensagem para a Máquina Virtual 2
        message_to_send = input("Insira a menssagem a ser encriptada: ")
        client_socket.sendall(message_to_send.encode())

        print('Enviando mensagem...\n')

        for i in range(3):
            print(i)
            time.sleep(1)
        print('Mensagem enviada.\n')

        # Recebe mensagem encriptada da Máquina Virtual 2
        encrypted_data = client_socket.recv(4096)
        print(f'Bytes da Mensagem encriptada recebida: \n{encrypted_data}\n')

        print('Disserializando mensagem...\n')
        for i in range(3):
            print(i)
            time.sleep(1)
        # Desserializa a mensagem encriptada e a chave privada
        encrypted_message, private_key_bytes = pickle.loads(encrypted_data)
        print(f'Bytes da Mensagem disserializada:\n1. mensagem encriptada disserializada recebida: {encrypted_message}\n\n2. Chave privada recebida: {private_key_bytes}\n')
        # Recupera a chave privada do bytes
        private_key = serialization.load_pem_private_key(
            private_key_bytes,
            password=None, # se tiver senha
            backend=default_backend()
        )
        print('Decriptando mensagem...\n')
        for i in range(3):
            print(i)
            time.sleep(1)
        # Decripta a mensagem usando a chave privada
        decrypted_message = private_key.decrypt( # semelhante à criptografia
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Decodifica a mensagem desencriptada e printar
        print("Mensagem decriptada recebida:", decrypted_message.decode())

    except Exception as e:
        print(f"Erro: {e}")

    finally:
        # Fecha o socket do cliente, independentemente de erros
        client_socket.close()

if __name__ == "__main__":
    main()
