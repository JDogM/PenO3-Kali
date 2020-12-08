import Ccmp
import WPA2
from binascii import b2a_hex

def decrypt(packet, round_keys, rounds):
    data = b2a_hex(packet.data)

    if len(data) % 32 == 0:
        nb_blocks = int(len(data) / 32)
    else:
        nb_blocks = int(len(data) / 32) + 1
    clear_text = str()

    for i in range(nb_blocks):
        block_string = Ccmp.const_nonce(packet)

        while len(block_string) < 30:
            block_string += '00'

        if i + 1 <= 0x0f:
            block_string += '0' + hex(i + 1)[2:]
        else:
            block_string += hex(i + 1)[2:]

        block = WPA2.make_matrix(block_string)
        block_encrypted = WPA2.encrypt_wpa2_data(block, round_keys, rounds)

        if len(data) >= 32:
            stream = data.decode('utf-8')[:32]
            data = data[32:]
        else:
            stream = data.decode('utf-8')

        stream_matrix = WPA2.make_matrix(stream)
        cipher = WPA2.xor(block_encrypted, stream_matrix[0])
        text = WPA2.matrix_to_string(cipher)
        clear_text += text
        
    print("---------------------------")
    print("Sender: ", packet.addr1, "\nReceiver: ", packet.addr2)
    print("Message: ")

    return filter_packets(clear_text)

def filter_packets(message):
    alfabet = [chr(elem) for elem in range(48, 123)]
    filtered_message = ""

    for elem in message:
        if elem == " ":
            filtered_message += " "
        if elem in alfabet or elem.isdigit():
            filtered_message += elem
        else:
            continue

    if len(filtered_message) < 5:
        return ''

    return filtered_message
