"""Draw fictional document photos for tests and demos (Pillow only, no network).

  uv run python scripts/make_photo_fixtures.py [out_dir]     default: demo/photos

Every name and number is made up. The SSN uses 987-65-4329, from the range reserved for advertising.
"""

from __future__ import annotations

import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

CARDS = {
    "ssn_card_jordan.png": {
        "size": (860, 520), "bg": (236, 242, 250), "band": (40, 76, 140),
        "lines": [
            (34, "SOCIAL SECURITY (SAMPLE)", True),
            (20, "THIS NUMBER HAS BEEN ESTABLISHED FOR", False),
            (44, "987-65-4329", True),
            (30, "JORDAN OKAFOR", True),
            (18, "FICTIONAL TEST CARD. NOT A REAL DOCUMENT.", False),
        ],
    },
    "insurance_card_maya.png": {
        "size": (900, 540), "bg": (245, 250, 244), "band": (30, 110, 70),
        "lines": [
            (34, "BLUE PINE HEALTH (FICTIONAL)", True),
            (24, "Member: Maya Okafor", False),
            (30, "Member ID: BPF-5530-2178", True),
            (24, "Group number: 77120", False),
            (24, "Plan: PPO Silver   Copay: $25", False),
            (18, "Sample card for testing. Not real coverage.", False),
        ],
    },
    "passport_page_dana.jpg": {
        "size": (920, 600), "bg": (250, 246, 236), "band": (120, 40, 50),
        "lines": [
            (34, "PASSPORT (FICTIONAL)", True),
            (24, "Surname: OKAFOR", False),
            (24, "Given names: DANA", False),
            (30, "Passport number: X30981455", True),
            (24, "Date of birth: 14 MAR 1982", False),
            (24, "Date of expiry: 02 JUN 2031", False),
            (18, "Sample page for testing. Not a travel document.", False),
        ],
    },
}


def font(size: int, bold: bool):
    for name in (("DejaVuSans-Bold.ttf" if bold else "DejaVuSans.ttf"),
                 ("Arial Bold.ttf" if bold else "Arial.ttf"), "Helvetica.ttc"):
        try:
            return ImageFont.truetype(name, size)
        except OSError:
            continue
    return ImageFont.load_default(size=size)


def draw(spec: dict) -> Image.Image:
    w, h = spec["size"]
    im = Image.new("RGB", (w, h), spec["bg"])
    d = ImageDraw.Draw(im)
    d.rectangle([0, 0, w, 18], fill=spec["band"])
    d.rectangle([0, h - 18, w, h], fill=spec["band"])
    d.rounded_rectangle([12, 30, w - 12, h - 30], radius=18, outline=spec["band"], width=3)
    y = 60
    for size, text, bold in spec["lines"]:
        d.text((48, y), text, fill=(20, 20, 24), font=font(size, bold))
        y += int(size * 1.9)
    return im


def main(out: Path) -> list[Path]:
    out.mkdir(parents=True, exist_ok=True)
    paths = []
    for name, spec in CARDS.items():
        p = out / name
        draw(spec).save(p, quality=92) if p.suffix == ".jpg" else draw(spec).save(p)
        paths.append(p)
    return paths


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[1] / "demo" / "photos"
    for p in main(target):
        print(p)
