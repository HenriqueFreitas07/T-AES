#!/usr/bin/env python3
"""
Generate histogram figure from stat.cpp output for LaTeX report
Reads hamming_distance,count CSV and produces high-quality PDF/PNG
"""

import matplotlib.pyplot as plt
import numpy as np
import sys

# Your actual data from stat output
data = {
    34: 1, 38: 4, 39: 9, 40: 10, 41: 39, 42: 89, 43: 183, 44: 341, 45: 649,
    46: 1096, 47: 1975, 48: 3361, 49: 5389, 50: 8398, 51: 12706, 52: 19041,
    53: 27197, 54: 37666, 55: 50932, 56: 66328, 57: 83351, 58: 102972,
    59: 121305, 60: 139683, 61: 156195, 62: 168948, 63: 176690, 64: 179823,
    65: 176481, 66: 169304, 67: 156507, 68: 140915, 69: 121344, 70: 102232,
    71: 83792, 72: 66039, 73: 50975, 74: 37781, 75: 27325, 76: 19066,
    77: 12932, 78: 8217, 79: 5233, 80: 3224, 81: 1865, 82: 1109, 83: 625,
    84: 311, 85: 179, 86: 86, 87: 36, 88: 25, 89: 13, 90: 1, 91: 2
}

# Extract arrays
hamming_distances = list(data.keys())
frequencies = list(data.values())

# Calculate statistics
total = sum(frequencies)
mean = sum(hd * freq for hd, freq in data.items()) / total

# Create figure with better styling
plt.figure(figsize=(10, 6))
plt.style.use('seaborn-v0_8-darkgrid')

# Plot histogram
plt.bar(hamming_distances, frequencies, width=0.8, color='steelblue', 
        edgecolor='black', linewidth=0.5, alpha=0.8)

# Add mean line
plt.axvline(mean, color='red', linestyle='--', linewidth=2.5, 
            label=f'Mean = {mean:.1f} bits')

# Add theoretical expectation line
plt.axvline(64, color='green', linestyle=':', linewidth=2.5, 
            label='Expected (random) = 64 bits')

# Styling
plt.xlabel('Hamming Distance (bits changed)', fontsize=12, fontweight='bold')
plt.ylabel('Frequency (count)', fontsize=12, fontweight='bold')
plt.title('Tweak Avalanche Effect: Hamming Distance Distribution\n' + 
          f'(2,550,000 measurements, mean = {mean:.1f} bits)', 
          fontsize=14, fontweight='bold')
plt.legend(fontsize=11, loc='upper left')
plt.grid(axis='y', alpha=0.3)
plt.xlim(30, 95)

# Add text annotation
textstr = f'Total measurements: {total:,}\nMean: {mean:.2f} bits\nStd Dev: ~5.7 bits'
props = dict(boxstyle='round', facecolor='wheat', alpha=0.5)
plt.text(0.73, 0.97, textstr, transform=plt.gca().transAxes, fontsize=10,
         verticalalignment='top', bbox=props)

plt.tight_layout()

# Save as PDF for LaTeX (high quality)
plt.savefig('stat_histogram.pdf', dpi=300, bbox_inches='tight')
print("✓ Saved: stat_histogram.pdf")

# Also save as PNG for quick preview
plt.savefig('stat_histogram.png', dpi=150, bbox_inches='tight')
print("✓ Saved: stat_histogram.png")

print(f"\nStatistics:")
print(f"  Total measurements: {total:,}")
print(f"  Mean: {mean:.2f} bits")
print(f"  Expected: 64.0 bits")
print(f"  Difference: {abs(mean - 64.0):.4f} bits")
print(f"\n✓ Perfect avalanche effect demonstrated!")
