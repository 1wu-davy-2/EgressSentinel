"""从 icon.svg 的设计生成 PNG 图标（512/192/180），用于 favicon/apple-touch-icon/og:image。"""

from PIL import Image, ImageDraw


def lerp(a, b, t):
    return tuple(round(a[i] + (b[i] - a[i]) * t) for i in range(3))


C1, C2 = (52, 211, 153), (34, 211, 238)  # #34d399 -> #22d3ee


def make(size: int, scale: int = 8) -> Image.Image:
    s = 64 * scale  # 64 设计网格，放大抗锯齿
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    grad = Image.new("RGBA", (s, s))
    px = grad.load()
    for y in range(s):
        for x in range(s):
            px[x, y] = lerp(C1, C2, (x + y) / (2 * s)) + (255,)
    mask = Image.new("L", (s, s), 0)
    ImageDraw.Draw(mask).rounded_rectangle([0, 0, s - 1, s - 1], radius=int(s * 0.219), fill=255)
    img.paste(grad, (0, 0), mask)
    d = ImageDraw.Draw(img)
    w = int(3.6 * scale)
    white = (255, 255, 255, 255)
    # 盾牌轮廓（与 icon.svg 同路径）
    shield = [(32, 11), (46, 17.5), (46, 31), (46, 41.5), (32, 52.5), (18, 41.5), (18, 31), (18, 17.5)]
    d.line([(x * scale, y * scale) for x, y in shield], fill=white, width=w, joint="curve")
    # 出站箭头（斜线 + 圆角端点 + 直角箭头头部弧线近似）
    d.line(
        [(25.5 * scale, 38.5 * scale), (37.5 * scale, 26.5 * scale)],
        fill=white,
        width=w,
    )
    for cap in [(25.5 * scale, 38.5 * scale), (37.5 * scale, 26.5 * scale)]:
        r = w // 2 - 2
        d.ellipse([cap[0] - r, cap[1] - r, cap[0] + r, cap[1] + r], fill=white)
    # 箭头头部：横线 + 竖线（圆角端点）
    d.line([(30.5 * scale, 25.5 * scale), (38 * scale, 25.5 * scale)], fill=white, width=w)
    d.line([(38 * scale, 25.5 * scale), (38 * scale, 33 * scale)], fill=white, width=w)
    for cap in [(30.5 * scale, 25.5 * scale), (38 * scale, 33 * scale)]:
        r = w // 2 - 2
        d.ellipse([cap[0] - r, cap[1] - r, cap[0] + r, cap[1] + r], fill=white)
    return img.resize((size, size), Image.LANCZOS)


if __name__ == "__main__":
    import pathlib

    out = pathlib.Path(__file__).resolve().parent.parent / "website"
    for size, name in [(512, "icon-512.png"), (192, "icon-192.png"), (180, "icon-180.png")]:
        make(size).save(out / name)
        print("saved", out / name)
