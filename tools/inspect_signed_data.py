#!/usr/bin/env python3
import rclpy
from rclpy.node import Node
import base64
import binascii
from custom_msgs.msg import SignedData

class Inspector(Node):
    def __init__(self):
        super().__init__('signed_data_inspector')
        self.sub = self.create_subscription(SignedData, 'secure_topic', self.cb, 1)
        self.received = False

    def cb(self, msg: SignedData):
        if self.received:
            return
        self.received = True

        print('--- SignedData message ---')
        print('data (base64) length:', len(msg.data))
        print('signature (base64) length:', len(msg.signature))
        print('iv (base64) length:', len(msg.iv))
        try:
            ciphertext = base64.b64decode(msg.data)
            signature = base64.b64decode(msg.signature)
            iv = base64.b64decode(msg.iv)
            tag = base64.b64decode(msg.tag) if hasattr(msg, 'tag') else b''
        except Exception as e:
            print('Base64 decode error:', e)
            rclpy.shutdown()
            return

        print('decoded ciphertext bytes:', len(ciphertext))
        print('decoded signature bytes:', len(signature))
        print('iv bytes:', len(iv))
        print('tag bytes:', len(tag))
        # Hex preview
        print('iv (hex):', binascii.hexlify(iv).decode()[:64])
        print('tag (hex):', binascii.hexlify(tag).decode()[:64])
        print('ciphertext (hex preview):', binascii.hexlify(ciphertext[:24]).decode())
        # quick ASCII check
        try:
            txt = ciphertext.decode('utf-8')
            printable = sum(1 for c in txt if c.isprintable())
            print('ciphertext looks like text (first 100 chars):', txt[:100])
            print('printable chars fraction:', printable / len(txt))
        except Exception:
            print('ciphertext is not valid UTF-8 (expected for encrypted data)')

        rclpy.shutdown()


def main():
    rclpy.init()
    node = Inspector()
    try:
        rclpy.spin(node)
    except KeyboardInterrupt:
        pass
    rclpy.shutdown()

if __name__ == '__main__':
    main()
