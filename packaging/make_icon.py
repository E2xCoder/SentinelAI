"""Draw the SentinelAI application icon (needs Pillow; run by hand, outputs are committed)."""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw

SIZE = 1024
HERE = Path(__file__).parent


def draw() -> Image.Image:
    image = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    pen = ImageDraw.Draw(image)
    pen.rounded_rectangle((40, 40, SIZE - 40, SIZE - 40), radius=210, fill=(13, 19, 32, 255))
    green = (45, 212, 127, 255)
    shield = [(512, 190), (790, 310), (790, 500), (512, 850), (234, 500), (234, 310)]
    # Smooth lower edge: sample a curve from the shoulders down to the tip.
    left = [(234, 500), (250, 590), (300, 680), (380, 770), (512, 850)]
    right = [(512, 850), (644, 770), (724, 680), (774, 590), (790, 500)]
    outline = [shield[0], shield[1], *reversed(right), *reversed(left[:-1]), shield[5]]
    pen.line([*outline, outline[0], outline[1]], fill=green, width=58, joint="curve")
    pen.line([(390, 520), (480, 610), (650, 430)], fill=green, width=62, joint="curve")
    for x, y in ((390, 520), (650, 430)):
        pen.ellipse((x - 31, y - 31, x + 31, y + 31), fill=green)
    return image


def main() -> None:
    image = draw()
    image.resize((256, 256), Image.LANCZOS).save(HERE / "icon.png")
    sizes = [(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
    image.save(HERE / "icon.ico", sizes=sizes)
    image.save(HERE / "icon.icns")


if __name__ == "__main__":
    main()
