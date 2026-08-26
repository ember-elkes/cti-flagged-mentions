import json
import os
import requests
import tkinter as tk

CONFIG_PATH = os.path.join(os.environ["APPDATA"], "cti-capture", "config.json")
with open(CONFIG_PATH) as f:
    config = json.load(f)

def send_dispatch(url):
    """POST to repository_dispatch. Returns (ok: bool, message: str)."""
    r = requests.post(
        f"https://api.github.com/repos/{config['repo']}/dispatches",
        headers={"Authorization": f"Bearer {config['github_pat']}",
            "Accept": "application/vnd.github+json"},
        json={"event_type": "capture-url", "client_payload": {"url": url}},
        timeout=15,
    )
    if r.status_code == 204:
        return True, "Sent ✓ (check Notion in ~a minute)"
    return False, f"Failed: HTTP {r.status_code}"

def send_dispatch(url):
    """POST to repository_dispatch. Returns (ok: bool, message: str)."""
    r = requests.post(
        f"https://api.github.com/repos/{config['repo']}/dispatches",
        headers={"Authorization": f"Bearer {config['github_pat']}",
                "Accept": "application/vnd.github+json"},
        json={"event_type": "capture-url", "client_payload": {"url": url}},
        timeout=15,
    )
    if r.status_code == 204:
        return True, "Sent ✓ (check Notion in ~a minute)"
    return False, f"Failed: HTTP {r.status_code}"

def on_submit():
    url = entry.get().strip()
    if not url.startswith("http"):
        status_label.config(text="That doesn't look like a URL", fg="red")
        return
    ok, message = send_dispatch(url)
    status_label.config(text=message, fg="green" if ok else "red")
    entry.delete(0, tk.END)

# Initialize main application window
root = tk.Tk()
root.title("Dispatcher")
root.geometry("400x150")

# Create text entry widget
entry = tk.Entry(root, width=40)
entry.pack(pady=10)

# Fetch clipboard content and pre-fill the entry widget
try:
    clipboard_content = root.clipboard_get()
    entry.insert(0, clipboard_content)
except tk.TclError:
    pass  # Handle case where clipboard is empty or holds non-text data

# Create submission button
submit_btn = tk.Button(root, text="Submit", command=on_submit)
submit_btn.pack(pady=5)

# Create status label
status_label = tk.Label(root, text="", font=("Arial", 10, "bold"))
status_label.pack(pady=10)

# Start the application event loop
root.mainloop()

