def hex_decoder(to_decode):
    return bytes.fromhex(
        ''.join(
            to_decode
        )).decode('utf-8')
