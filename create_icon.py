"""
Create Aether AI Icon - Purple Circle with Audio Waves
Small, clean, professional icon for desktop app
"""

from PIL import Image, ImageDraw
import os

def create_aether_icon():
    # Create multiple sizes for Windows
    sizes = [16, 32, 48, 64, 128, 256]
    
    for size in sizes:
        # Create image with transparent background
        img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        
        # Purple gradient colors
        purple = (99, 102, 241)  # #6366f1 (indigo)
        
        # Draw circle background
        padding = size // 10
        draw.ellipse(
            [padding, padding, size - padding, size - padding],
            fill=purple,
            outline=None
        )
        
        # Draw audio wave bars (5 bars)
        bar_width = size // 20
        bar_gap = size // 25
        center_x = size // 2
        center_y = size // 2
        
        # Heights for 5 bars (center is tallest)
        heights = [0.3, 0.5, 0.7, 0.5, 0.3]
        
        start_x = center_x - (2.5 * (bar_width + bar_gap))
        
        for i, height_ratio in enumerate(heights):
            bar_height = int(size * height_ratio * 0.6)
            x = int(start_x + i * (bar_width + bar_gap))
            y_top = center_y - bar_height // 2
            y_bottom = center_y + bar_height // 2
            
            draw.rectangle(
                [x, y_top, x + bar_width, y_bottom],
                fill=(255, 255, 255, 255)  # White bars
            )
        
        # Save PNG
        img.save(f'ui/public/icon_{size}x{size}.png', 'PNG')
        print(f'[OK] Created icon_{size}x{size}.png')
    
    # Create ICO file (for Windows)
    print("\n[INFO] Creating .ico file...")
    
    # Load all sizes
    images = []
    for size in sizes:
        images.append(Image.open(f'ui/public/icon_{size}x{size}.png'))
    
    # Save as ICO
    os.makedirs('ui/assets', exist_ok=True)
    images[0].save(
        'ui/assets/icon.ico',
        format='ICO',
        sizes=[(s, s) for s in sizes]
    )
    print('[OK] Created icon.ico')
    
    # Create 512x512 for high-res displays
    img_512 = Image.new('RGBA', (512, 512), (0, 0, 0, 0))
    draw_512 = ImageDraw.Draw(img_512)
    
    purple = (99, 102, 241)
    padding_512 = 50
    
    # Circle
    draw_512.ellipse(
        [padding_512, padding_512, 512 - padding_512, 512 - padding_512],
        fill=purple
    )
    
    # Bars
    bar_width_512 = 25
    bar_gap_512 = 20
    center_512 = 256
    
    heights = [0.3, 0.5, 0.7, 0.5, 0.3]
    start_x_512 = center_512 - (2.5 * (bar_width_512 + bar_gap_512))
    
    for i, height_ratio in enumerate(heights):
        bar_height = int(512 * height_ratio * 0.6)
        x = int(start_x_512 + i * (bar_width_512 + bar_gap_512))
        y_top = center_512 - bar_height // 2
        y_bottom = center_512 + bar_height // 2
        
        draw_512.rectangle(
            [x, y_top, x + bar_width_512, y_bottom],
            fill=(255, 255, 255)
        )
    
    img_512.save('ui/public/icon_512x512.png', 'PNG')
    print('[OK] Created icon_512x512.png (high-res)')
    
    print('\n[SUCCESS] All icons created successfully!')
    print('\nIcon locations:')
    print('   - ui/assets/icon.ico (Windows installer)')
    print('   - ui/public/icon_*.png (Various sizes)')

if __name__ == '__main__':
    print('Creating Aether AI Icons...\n')
    create_aether_icon()
