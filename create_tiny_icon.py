"""
Create TINY Aether AI Icon - Minimal design for taskbar
Very small, very simple, very clean
"""

from PIL import Image, ImageDraw
import os

def create_tiny_icon():
    # Create tiny taskbar icon (16x16 and 32x32)
    sizes = [16, 32]
    
    for size in sizes:
        # Create image with transparent background
        img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        
        # Purple color
        purple = (99, 102, 241)  # #6366f1
        
        # Draw SMALL circle (extra padding for tiny look)
        if size == 16:
            padding = 2  # Very small circle for 16px
        else:
            padding = 4  # Small circle for 32px
            
        draw.ellipse(
            [padding, padding, size - padding, size - padding],
            fill=purple,
            outline=None
        )
        
        # Draw 3 bars instead of 5 (simpler for tiny size)
        if size == 16:
            bar_width = 1
            bar_gap = 1
        else:
            bar_width = 2
            bar_gap = 2
        
        center_x = size // 2
        center_y = size // 2
        
        # Heights for 3 bars (center tallest)
        heights = [0.25, 0.4, 0.25]
        
        start_x = center_x - (1.5 * (bar_width + bar_gap))
        
        for i, height_ratio in enumerate(heights):
            bar_height = int(size * height_ratio * 0.5)
            x = int(start_x + i * (bar_width + bar_gap))
            y_top = center_y - bar_height // 2
            y_bottom = center_y + bar_height // 2
            
            draw.rectangle(
                [x, y_top, x + bar_width, y_bottom],
                fill=(255, 255, 255, 255)  # White bars
            )
        
        # Save PNG
        filename = f'ui/public/icon_tiny_{size}x{size}.png'
        img.save(filename, 'PNG')
        print(f'[OK] Created icon_tiny_{size}x{size}.png - Extra small!')
    
    print('\n[SUCCESS] Tiny icons created!')
    print('These are MUCH smaller and simpler')
    print('\nLocations:')
    print('   - ui/public/icon_tiny_16x16.png (Extra tiny)')
    print('   - ui/public/icon_tiny_32x32.png (Tiny)')

if __name__ == '__main__':
    print('Creating TINY Aether AI Icons...\n')
    create_tiny_icon()
