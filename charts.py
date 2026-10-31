"""Server-side charts for the metrics dashboard. Labels are escaped, so no chart library is needed."""
import html, math
from datetime import timedelta
from markupsafe import Markup

HEAT_STEPS = ("#184f95", "#256abf", "#3987e5", "#6da7ec", "#b7d3f6")  # one hue, fewer to more
VERDICT_ORDER = ("true_positive", "benign", "needs_more_info")
SEVERITY_ORDER = ("critical", "high", "medium", "low", "unrated")
BUCKETS = ((6, timedelta(minutes=5), "%H:%M"), (72, timedelta(hours=1), "%m-%d %H:00"), (None, timedelta(days=1), "%Y-%m-%d"))


def _esc(value):
    return html.escape(str(value), quote=True)


def _tip(label, value):
    return f'data-tip-label="{_esc(label)}" data-tip-value="{_esc(value)}" aria-label="{_esc(label)}: {_esc(value)}"'


def _nice_ceiling(value):
    if value <= 4:
        return max(value, 1)
    magnitude = 10 ** math.floor(math.log10(value))
    for step in (1, 2, 2.5, 5, 10):
        if step * magnitude >= value:
            return int(step * magnitude)
    return value


def time_series(times):
    """Count detections in buckets sized to the time span, keeping empty buckets."""
    if not times:
        return []
    start, end = min(times), max(times)
    span_hours = (end - start).total_seconds() / 3600
    size, pattern = next((b[1], b[2]) for b in BUCKETS if b[0] is None or span_hours <= b[0])
    size_seconds = size.total_seconds()
    origin = start - timedelta(seconds=start.timestamp() % size_seconds)
    counts = {}
    for moment in times:
        slot = int((moment - origin).total_seconds() // size_seconds)
        counts[slot] = counts.get(slot, 0) + 1
    return [((origin + slot * size).strftime(pattern), counts.get(slot, 0)) for slot in range(max(counts) + 1)]


def _column(x, width, base, height):
    radius = min(4, width / 2, height)
    top = base - height
    return (f"M{x:.1f} {base}V{top + radius:.1f}Q{x:.1f} {top:.1f} {x + radius:.1f} {top:.1f}"
            f"H{x + width - radius:.1f}Q{x + width:.1f} {top:.1f} {x + width:.1f} {top + radius:.1f}V{base}Z")


def column_chart(points, title):
    if not points:
        return Markup('<p class="empty">No detections yet.</p>')
    width, height, left, top, bottom = 760, 240, 34, 22, 26
    plot_width, plot_height, base = width - left - 8, height - top - bottom, height - bottom
    peak = max(value for _, value in points)
    ceiling = _nice_ceiling(peak)
    band = plot_width / len(points)
    bar = min(24, band - 2 if band > 4 else band)
    parts = [f'<svg class="chart" viewBox="0 0 {width} {height}" role="group" aria-label="{_esc(title)}">']
    for fraction in (0, .5, 1):
        y = base - fraction * plot_height
        tick = ceiling * fraction
        parts.append(f'<line class="{"axis" if fraction == 0 else "grid"}" x1="{left}" x2="{width - 8}" y1="{y:.1f}" y2="{y:.1f}"/>')
        if tick == int(tick):
            parts.append(f'<text class="tick" x="{left - 8}" y="{y + 4:.1f}" text-anchor="end">{int(tick)}</text>')
    every = max(1, math.ceil(len(points) / 7))
    labelled_peak = False
    for index, (label, value) in enumerate(points):
        center = left + band * index + band / 2
        if index % every == 0:
            parts.append(f'<text class="tick" x="{center:.1f}" y="{height - 8}" text-anchor="middle">{_esc(label)}</text>')
        if not value:
            continue
        bar_height = max(2, value / ceiling * plot_height)
        focus = f'class="mark" tabindex="0" role="img" {_tip(label + " UTC", f"{value} detections")}'
        parts.append(f'<g {focus}><rect class="hit" x="{center - band / 2:.1f}" y="{top}" width="{band:.1f}" height="{plot_height}"/>'
                     f'<path class="bar" d="{_column(center - bar / 2, bar, base, bar_height)}"/></g>')
        if value == peak and not labelled_peak:
            labelled_peak = True
            parts.append(f'<text class="peak" x="{center:.1f}" y="{base - bar_height - 7:.1f}" text-anchor="middle">{value}</text>')
    parts.append("</svg>")
    return Markup("".join(parts))


def ranked_bars(rows, unit="detections"):
    """Horizontal bars, largest first. One series, so every bar shares a colour."""
    if not rows:
        return Markup('<p class="empty">No data yet.</p>')
    peak = max(value for _, value in rows)
    parts = ['<div class="ranked">']
    for label, value in rows:
        share = max(1.5, value / peak * 100)
        parts.append(f'<div class="ranked-row mark" tabindex="0" role="img" {_tip(label, f"{value} {unit}")}>'
                     f'<span class="ranked-label">{_esc(label)}</span>'
                     f'<span class="ranked-track"><span class="ranked-bar" style="width:{share * .86:.1f}%"></span>'
                     f'<span class="ranked-value">{value}</span></span></div>')
    parts.append("</div>")
    return Markup("".join(parts))


def segmented_bar(parts_in, title, css_prefix):
    """One whole split into named parts, with a legend. Parts at zero draw nothing."""
    parts_in = [(name, value) for name, value in parts_in if value]
    total = sum(value for _, value in parts_in)
    if not total:
        return Markup('<p class="empty">No data yet.</p>')
    blocks, legend = [], []
    for name, value in parts_in:
        share = value / total
        text = _esc(value) if share >= .08 else ""
        tip = _tip(name.replace("_", " "), f"{value} of {total} ({share:.0%})")
        blocks.append(f'<span class="segment {css_prefix}-{_esc(name)} mark" tabindex="0" role="img" {tip} style="flex:{value} 1 0">{text}</span>')
        legend.append(f'<span class="legend-item"><span class="swatch {css_prefix}-{_esc(name)}"></span>{_esc(name.replace("_", " ").capitalize())}</span>')
    return Markup(f'<div class="segments" role="group" aria-label="{_esc(title)}">{"".join(blocks)}</div>'
                  f'<div class="legend">{"".join(legend)}</div>')


def heatmap(times, days=7):
    """Detections by day and UTC hour for the most recent active days."""
    if not times:
        return Markup('<p class="empty">No detections yet.</p>')
    counts = {}
    for moment in times:
        key = (moment.strftime("%Y-%m-%d"), moment.hour)
        counts[key] = counts.get(key, 0) + 1
    labels = sorted({day for day, _ in counts})[-days:]
    peak = max(counts.values())
    parts = ['<div class="heat-wrap"><div class="heat" role="group" aria-label="Detections by day and hour"><span></span>']
    parts.extend(f'<span class="heat-hour">{hour if hour % 3 == 0 else ""}</span>' for hour in range(24))
    for day in labels:
        parts.append(f'<span class="heat-day">{day[5:]}</span>')
        for hour in range(24):
            value = counts.get((day, hour), 0)
            if value:
                step = HEAT_STEPS[min(len(HEAT_STEPS) - 1, math.ceil(value / peak * len(HEAT_STEPS)) - 1)]
                parts.append(f'<span class="cell mark" tabindex="0" role="img" style="background:{step}" {_tip(f"{day} {hour:02}:00 UTC", f"{value} detections")}></span>')
            else:
                parts.append('<span class="cell"></span>')
    parts.append('</div></div><div class="legend"><span class="scale-label">Fewer</span>')
    parts.extend(f'<span class="swatch" style="background:{step}"></span>' for step in HEAT_STEPS)
    parts.append(f'<span class="scale-label">More (peak {peak})</span></div>')
    return Markup("".join(parts))
