import base64
import zlib
import json
import re
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox


def fix_padding(s: str) -> str:
    s = "".join(s.split())
    return s + "=" * ((4 - (len(s) % 4)) % 4)


def maybe_decompress(data: bytes) -> bytes:
    for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS, zlib.MAX_WBITS | 16):
        try:
            return zlib.decompress(data, wbits=wbits)
        except zlib.error:
            pass
    return data


def clear_tags():
    for tag in output.tag_names():
        output.tag_remove(tag, "1.0", tk.END)


def highlight_json(text: str):
    clear_tags()

    patterns = {
        "key": r'(?<=")[^"]+(?="\s*:)',
        "string": r'"([^"\\]|\\.)*"',
        "number": r'\b-?\d+(\.\d+)?([eE][+-]?\d+)?\b',
        "bool": r'\b(true|false|null)\b',
        "brace": r'[{}\[\]]'
    }

    for tag, pattern in patterns.items():
        for match in re.finditer(pattern, text):
            start = f"1.0+{match.start()}c"
            end = f"1.0+{match.end()}c"
            output.tag_add(tag, start, end)


def decode_blob():
    output.delete("1.0", tk.END)

    b64 = input_box.get("1.0", tk.END).strip()
    if not b64:
        messagebox.showerror("Error", "No input provided")
        return

    try:
        b64 = fix_padding(b64)
        raw = base64.b64decode(b64, validate=False)
        raw = maybe_decompress(raw)
        text = raw.decode("utf-8", errors="replace").strip()

        try:
            obj = json.loads(text)
            text = json.dumps(obj, indent=2, ensure_ascii=False)
            output.insert(tk.END, text)
            highlight_json(text)
        except Exception:
            output.insert(tk.END, text)

    except Exception as e:
        output.insert(tk.END, f"[ERROR]\n{e}")


# ---------- GUI ----------
root = tk.Tk()
root.title("Base64 / Zlib Decoder (JSON Highlighting)")
root.geometry("900x650")

frame = ttk.Frame(root, padding=10)
frame.pack(fill=tk.BOTH, expand=True)

ttk.Label(frame, text="Base64 Input").pack(anchor="w")

input_box = scrolledtext.ScrolledText(frame, height=8)
input_box.pack(fill=tk.X, pady=5)

ttk.Button(frame, text="Decode", command=decode_blob).pack(pady=6)

ttk.Label(frame, text="Output").pack(anchor="w")

output = scrolledtext.ScrolledText(frame)
output.pack(fill=tk.BOTH, expand=True)

# ---------- Highlight Styles ----------
output.tag_configure("key", foreground="#268bd2")      # blue
output.tag_configure("string", foreground="#2aa198")   # green
output.tag_configure("number", foreground="#d33682")   # pink/orange
output.tag_configure("bool", foreground="#6c71c4")     # purple
output.tag_configure("brace", foreground="#93a1a1")    # gray

root.mainloop()
