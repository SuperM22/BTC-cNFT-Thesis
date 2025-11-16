#!/usr/bin/env python3
import argparse, json, struct, sys
from pathlib import Path

from PIL import Image

def load_png(path: str, mode: str):
    if mode not in ("L", "RGB", "RGBA"):
        raise ValueError("mode must be one of: L, RGB, RGBA")
    with Image.open(path) as im:
        im = im.convert(mode)
        w, h = im.size
        # getdata returns pixels in row-major scanline order
        if mode == "L":
            data = list(im.getdata())  # [u8, u8, ...] length = w*h
            channels = 1
        else:
            # [(r,g,b) ...] or [(r,g,b,a) ...] -> flatten
            pix = list(im.getdata())
            channels = len(pix[0])
            # flatten to [u8 ...] length = w*h*channels
            data = [c for tup in pix for c in tup]
        return w, h, channels, data

def write_json(out_path: str, w: int, h: int, c: int, data):
    obj = {"width": w, "height": h, "channels": c, "data": data}
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(obj, f, separators=(",", ":"))

def write_binary(out_path: str, w: int, h: int, c: int, data):
    """
    Binary format (little-endian):
      magic:  b'IMAT'         (4 bytes)
      version: u32 = 1        (4 bytes)
      width:   u32            (4 bytes)
      height:  u32            (4 bytes)
      channels:u32            (4 bytes)
      depth:   u32 = 8        (4 bytes)  # bits per channel
      payload: u8[w*h*c]      (row-major, top-left -> bottom-right)
    """
    with open(out_path, "wb") as f:
        f.write(b"IMAT")
        f.write(struct.pack("<I", 1))          # version
        f.write(struct.pack("<III", w, h, c))
        f.write(struct.pack("<I", 8))          # depth
        f.write(bytes(data))

def main():
    p = argparse.ArgumentParser(description="Convert a PNG to a matrix for Rust.")
    p.add_argument("image", help="Path to input PNG (other formats supported).")
    p.add_argument("--mode", default="RGB", choices=["L", "RGB", "RGBA"],
                   help="Pixel mode. Default: RGB")
    out = p.add_mutually_exclusive_group(required=True)
    out.add_argument("--json", metavar="OUT.json", help="Write JSON {width,height,channels,data}.")
    out.add_argument("--bin", metavar="OUT.bin", help="Write compact binary file.")
    args = p.parse_args()

    w, h, c, data = load_png(args.image, args.mode)
    print(f"Loaded {args.image}  mode={args.mode}  {w}x{h}x{c}  bytes={len(data)}")

    if args.json:
        write_json(args.json, w, h, c, data)
        print(f"Wrote JSON -> {args.json}")
    else:
        write_binary(args.bin, w, h, c, data)
        print(f"Wrote BIN  -> {args.bin}")

if __name__ == "__main__":
    main()
