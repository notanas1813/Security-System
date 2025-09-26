# modules/crypto/file_chunk.py
import os
from modules.utils.config import BLOCK_SIZE

def split_file(input_path: str):
    """Trả về list path block."""
    blocks = []
    with open(input_path,'rb') as f:
        idx = 0
        while True:
            chunk = f.read(BLOCK_SIZE)
            if not chunk: break
            out = f"{input_path}.part{idx}"
            with open(out,'wb') as bf: bf.write(chunk)
            blocks.append(out)
            idx += 1
    return blocks

def join_blocks(block_paths: list, out_path: str):
    with open(out_path,'wb') as out:
        for p in block_paths:
            with open(p,'rb') as bf:
                out.write(bf.read())