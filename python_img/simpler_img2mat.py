#!/usr/bin/env python3
import sys
import cv2

# Usage:
#   python3 simpler_img2mat.py input.png output.bin
# Produces raw bytes: RGB row-major, shape = [H][W][3] (uint8)

inp, out = sys.argv[1], sys.argv[2]
rgb = cv2.cvtColor(cv2.imread(inp, cv2.IMREAD_COLOR), cv2.COLOR_BGR2RGB)
rgb.tofile(out)
print(rgb.shape)  # prints: (H, W, 3)
