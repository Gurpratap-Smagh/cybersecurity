from PIL import Image, ImageOps, ImageEnhance
input_f = "your card pic"
output_f = "output.png"
def extract_yellow_dots(input_path, output_path):
    # 1. Open the high-res scan
    img = Image.open(input_path)
    
    # 2. Convert to CMYK (this isolates the inks used by the printer)
    # The 3rd channel [C, M, Y, K] is the Yellow one.
    cmyk = img.convert('CMYK')
    c, m, y, k = cmyk.split()
    
    # 3. Invert the Yellow channel 
    # This makes the yellow dots appear as BLACK dots on a WHITE background
    inverted_y = ImageOps.invert(y)
    
    # 4. Boost Contrast (The "Crystal Clear" step)
    # We push contrast to 10x or more to kill gray noise and pop the dots
    enhancer = ImageEnhance.Contrast(inverted_y)
    crystal_clear = enhancer.enhance(45.0) 
    
    # 5. Thresholding (Optional: turns everything into pure black or pure white)
    # This removes the "paper grain" entirely
    crystal_clear = crystal_clear.point(lambda p: p if p < 100 else 255)

    # Save the result
    crystal_clear.save(output_path)
    print(f"Extraction complete! Saved to: {output_path}")

# Run it on your file
extract_yellow_dots(input_f, output_f)
