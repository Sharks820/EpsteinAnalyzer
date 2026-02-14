import fitz

doc = fitz.open('C:\\Users\\Conner\\EpsteinAnalyzer\\data\\datasets\\dataset_1\\EFTA00000035.pdf')
page = doc[0]
print(f'Page size: {page.rect}')
print(f'Image list: {page.get_images()}')
# Check for any drawings or annotations
annots = list(page.annots()) if page.annots() else []
print(f'Annots: {annots}')
# Get full raw text
text = page.get_text('dict')
blocks = text.get('blocks', [])
print(f'Blocks: {len(blocks)}')
for block in blocks:
    print(block)
