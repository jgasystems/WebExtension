import struct
import hashlib
import string

def get_pub_key_from_crx(crx_file):
    with open(crx_file, 'rb') as f:
        data = f.read()
    header = struct.unpack('<4sIII', data[:16])
    pubkey = struct.unpack('<%ds' % header[2], data[16:16+header[2]])[0]
    #print(pubkey)
    return pubkey

def get_extension_id(crx_file):
    pubkey = get_pub_key_from_crx(crx_file)
    digest = hashlib.sha256(pubkey).hexdigest()

    trans = str.maketrans('0123456789abcdef', string.ascii_lowercase[:16])
    return str.translate(digest[:32], trans)

if __name__ == '__main__':
    import sys
    #if len(sys.argv) != 2:
    #    print ('usage: %s crx_file' % sys.argv[0])

    print (get_extension_id(sys.argv[1]))