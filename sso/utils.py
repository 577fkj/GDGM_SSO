import ddddocr

def pad(b: bytearray, blocksize: int) -> bytearray:
    pad_data = b''
    pad_len = blocksize - len(b) % blocksize
    if pad_len == 16 or pad_len == 0:
        return b
    for i in range(pad_len):
        pad_data += bytes([pad_len])
    return b + pad_data

def unpad(s: bytearray) -> bytearray:
    return s[:-s[-1]]

def ocr_code(img_bytes):
    ocr = ddddocr.DdddOcr(show_ad=False)
    return ocr.classification(img_bytes)