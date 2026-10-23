"""Génère packetphantom/web/land.json : grille de points posés sur les terres émergées.

Source : Natural Earth, ne_110m_land.geojson (domaine public)
https://github.com/nvkelso/natural-earth-vector/blob/master/geojson/ne_110m_land.geojson

Usage : python tools/globe_dots.py ne_110m_land.geojson packetphantom/web/land.json
L'espacement en longitude s'élargit vers les pôles pour garder une densité de points constante.
"""
from __future__ import annotations

import json
import math
import sys

STEP = 1.6   # degrés entre deux points


def inside(lon: float, lat: float, ring: list[list[float]]) -> bool:
    """Test du rayon (pair-impair) sur un anneau de coordonnées [lon, lat]."""
    hit = False
    for (x1, y1), (x2, y2) in zip(ring, ring[1:] + ring[:1], strict=True):
        if (y1 > lat) != (y2 > lat) and lon < (x2 - x1) * (lat - y1) / (y2 - y1) + x1:
            hit = not hit
    return hit


def polygons(geojson: dict):
    for feature in geojson["features"]:
        geometry = feature["geometry"]
        parts = [geometry["coordinates"]] if geometry["type"] == "Polygon" else geometry["coordinates"]
        for rings in parts:
            outer = rings[0]
            xs, ys = [p[0] for p in outer], [p[1] for p in outer]
            yield (min(xs), min(ys), max(xs), max(ys)), outer, rings[1:]


def main(source: str, target: str) -> None:
    with open(source, encoding="utf-8") as handle:
        shapes = list(polygons(json.load(handle)))
    dots: list[float] = []
    lat = -90 + STEP / 2
    while lat < 90:
        lon_step = STEP / max(math.cos(math.radians(lat)), 0.05)
        lon = -180 + lon_step / 2
        while lon < 180:
            for (x0, y0, x1, y1), outer, holes in shapes:
                if x0 <= lon <= x1 and y0 <= lat <= y1 and inside(lon, lat, outer) \
                        and not any(inside(lon, lat, hole) for hole in holes):
                    dots += [round(lat, 1), round(lon, 1)]
                    break
            lon += lon_step
        lat += STEP
    with open(target, "w", encoding="utf-8") as handle:
        json.dump({"source": "Natural Earth ne_110m_land (domaine public)", "step": STEP, "dots": dots},
                  handle, separators=(",", ":"))
    print(f"{len(dots) // 2} points -> {target}")


if __name__ == "__main__":
    main(*sys.argv[1:3])
