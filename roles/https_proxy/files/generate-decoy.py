"""Generate a small static site using only the Python standard library."""

import random
import sys
from pathlib import Path


def generate(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    title = f"{random.choice(('Quiet', 'Soft', 'Distant', 'Golden', 'Hidden', 'Open'))} {random.choice(('Horizons', 'Shapes', 'Reflections', 'Gardens', 'Waves', 'Spaces'))}"
    hue = random.randrange(360)
    shapes = []
    for _ in range(18):
        x, y, radius = random.randrange(800), random.randrange(480), random.randrange(30, 180)
        color = f"hsl({(hue + random.randrange(90)) % 360},55%,65%)"
        shapes.append(f'<circle cx="{x}" cy="{y}" r="{radius}" fill="{color}" opacity="0.45"/>')
    image = (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 800 480">'
        f'<rect width="800" height="480" fill="hsl({hue},25%,94%)"/>'
        + ''.join(shapes) + '</svg>\n'
    )
    (directory / 'art.svg').write_text(image, encoding='utf-8')
    (directory / 'robots.txt').write_text('User-agent: *\nDisallow: /\n', encoding='utf-8')
    html = f'''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="robots" content="noindex,nofollow">
  <title>{title}</title>
  <style>body{{max-width:50rem;margin:8vh auto;padding:0 1.5rem;font:17px/1.6 system-ui,sans-serif;color:#28323c}}img{{width:100%;height:auto;border-radius:12px}}</style>
</head>
<body>
  <main>
    <h1>{title}</h1>
    <p>A small study of colour, form, and light.</p>
    <img src="/art.svg" alt="An abstract composition of overlapping colourful circles" width="800" height="480">
  </main>
</body>
</html>
'''
    (directory / 'index.html').write_text(html, encoding='utf-8')


if __name__ == '__main__':
    generate(sys.argv[1])
