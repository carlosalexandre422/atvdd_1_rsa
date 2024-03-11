import socket
import pickle
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

def main():
    # Configurar o socket do cliente
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('localhost', 12345)  # Altere conforme necessário

    try:
        # Tentar conectar ao servidor
        client_socket.connect(server_address)

        # Enviar mensagem para a Máquina Virtual 2
        message_to_send = input("Insira a menssagem a ser encriptada: ")
        client_socket.sendall(message_to_send.encode())
        print('Mensagem enviada.\n')

        # Receber mensagem encriptada da Máquina Virtual 2
        encrypted_data = client_socket.recv(4096)
        print(f'Mensagem encriptada recebida: {encrypted_data}\n')

        # Desserializar a mensagem encriptada e a chave privada
        encrypted_message, private_key_bytes = pickle.loads(encrypted_data)
        print(f'Mensagem disserializada:\nmensagem encriptada disserializada recebida: {encrypted_message}\n\nbytes da chave privada recebida: {private_key_bytes}\n')
        # Recuperar a chave privada do bytes
        private_key = serialization.load_pem_private_key(
            private_key_bytes,
            password=None,  # Se tiver senha, forneça-a aqui
            backend=default_backend()
        )

        # Desencriptar a mensagem usando a chave privada
        decrypted_message = private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Decodificar a mensagem desencriptada e printar
        print("Mensagem desencriptada recebida:", decrypted_message.decode())

    except Exception as e:
        print(f"Erro: {e}")

    finally:
        # Fechar o socket do cliente, independentemente de erros
        client_socket.close()

if __name__ == "__main__":
    main()