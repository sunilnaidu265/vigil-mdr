"""Defang IOCs in the model's output. Small models miss some, so code makes sure."""
import re

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_SCHEME_RE = re.compile(r"\bhttp(s?)://", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b([\w.+-]+)@([\w-]+(?:\.[\w-]+)+)\b")
# domain = labels + a letters-only TLD; skips file names like upd.exe via the extension list
DOMAIN_RE = re.compile(r"\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b", re.IGNORECASE)
FILE_EXT = {"exe", "dll", "ps1", "bat", "cmd", "vbs", "js", "hta", "docm", "docx", "xlsm",
            "xlsx", "pdf", "zip", "rar", "7z", "msi", "lnk", "tmp", "dat", "log", "txt",
            "sys", "scr", "iso", "img", "jar", "py", "sh", "json", "xml", "ini", "cfg"}


def defang(text: str) -> str:
    if not isinstance(text, str):
        return text
    text = URL_SCHEME_RE.sub(lambda m: f"hxxp{m.group(1)}://", text)
    text = EMAIL_RE.sub(lambda m: f"{m.group(1)}[@]{m.group(2)}", text)
    text = IP_RE.sub(lambda m: m.group(0).replace(".", "[.]"), text)

    def _dom(m):
        d = m.group(1)
        if d.rsplit(".", 1)[-1].lower() in FILE_EXT:   # file name, leave it
            return d
        return d.replace(".", "[.]")
    return DOMAIN_RE.sub(_dom, text)


def defang_obj(obj, skip_keys=("event_ids", "verdict", "confidence", "severity", "type", "stage")):
    """Walk the result dict and defang every string except IDs and enums."""
    if isinstance(obj, dict):
        return {k: (v if k in skip_keys else defang_obj(v, skip_keys)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [defang_obj(v, skip_keys) for v in obj]
    return defang(obj)


if __name__ == "__main__":
    tests = ["Connected to 185.220.101.5:443", "Downloaded https://bad.com/a.ps1",
             "Contacted google.com and cdn.evil-site.net", "Mail from user@bad.com",
             r"Dropped C:\Users\ravi\AppData\Roaming\upd.exe", "Ran T1059.001",
             "Already 1[.]2[.]3[.]4 stays the same"]
    for t in tests:
        print(f"{t}\n  -> {defang(t)}")
