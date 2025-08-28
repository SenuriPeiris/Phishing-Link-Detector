import customtkinter as ctk
import re

# Initialize main window
root = ctk.CTk()
root.title("Phishing Link Detector")
root.geometry("900x750")

ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

# Suspicious keywords
suspicious_keywords = ['login', 'update', 'verify', 'secure', 'bank', 'account', 'password', 'confirm']

# Protection tips
default_safe_tip = ["✅ Good job! No issues detected."]
protection_tips_list = [
    "Do not click on suspicious links.",
    "Check the domain carefully; avoid mimics.",
    "Never enter credentials on unknown sites.",
    "Use multi-factor authentication (MFA).",
    "Keep antivirus and security software updated.",
    "Verify emails/messages before acting on them.",
    "Hover over links to preview the real URL.",
    "Avoid downloading attachments from unknown senders.",
    "Use a password manager to detect fake sites."
]

# Functions
def calculate_risk(url):
    score = 0
    reasons = []

    ip_pattern = r'http[s]?://(?:[0-9]{1,3}\.){3}[0-9]{1,3}'
    if re.match(ip_pattern, url):
        score += 3
        reasons.append("Uses IP address instead of domain")

    for word in suspicious_keywords:
        if word in url.lower():
            score += 2
            reasons.append(f"Contains suspicious word: '{word}'")

    subdomains = url.split('//')[-1].split('/')[0].split('.')
    if len(subdomains) > 3:
        score += 1
        reasons.append("Too many subdomains")

    domain = subdomains[-2] if len(subdomains) >= 2 else subdomains[0]
    if len(domain) > 20:
        score += 1
        reasons.append("Domain name is unusually long")

    if score > 10:
        score = 10

    return score, reasons

def update_textbox(textbox, items):
    textbox.configure(state="normal")
    textbox.delete("1.0", "end")
    for item in items:
        textbox.insert("end", f"- {item}\n")
    textbox.configure(state="disabled")

def check_url():
    url = url_entry.get().strip()
    if not url:
        return

    score, reasons = calculate_risk(url)

    if score > 2:
        status = "Phishing"
        color = "#e74c3c"
        icon = "⚠️"
        detected_reasons = reasons if reasons else ["Suspicious URL detected"]
        tips = protection_tips_list
    else:
        status = "Safe"
        color = "#2ecc71"
        icon = "✅"
        detected_reasons = default_safe_tip
        tips = []

    # Update result label
    result_label.configure(text=f"{icon} {url} → {status}", text_color=color)

    # Update risk meter
    risk_meter.set(score / 10)

    # Update detected issues and tips
    update_textbox(reason_textbox, detected_reasons)
    update_textbox(tips_textbox, tips)

    # Add to history
    history_textbox.configure(state="normal")
    history_textbox.insert("end", f"{url} → {status}\n")
    history_textbox.configure(state="disabled")

    url_entry.delete(0, "end")

def clear_history():
    history_textbox.configure(state="normal")
    history_textbox.delete("1.0", "end")
    history_textbox.configure(state="disabled")
    reason_textbox.configure(state="normal")
    reason_textbox.delete("1.0", "end")
    reason_textbox.configure(state="disabled")
    tips_textbox.configure(state="normal")
    tips_textbox.delete("1.0", "end")
    tips_textbox.configure(state="disabled")
    result_label.configure(text="", text_color="#000000")
    risk_meter.set(0)

def paste_clipboard():
    try:
        clipboard_text = root.clipboard_get().strip()
        url_entry.delete(0, "end")
        url_entry.insert(0, clipboard_text)
    except:
        result_label.configure(text="⚠️ Clipboard is empty!", text_color="#f39c12")

# Header
header_label = ctk.CTkLabel(root, text="Phishing Link Detector", font=("Arial", 20, "bold"))
header_label.pack(pady=15)

# URL Input Frame
url_frame = ctk.CTkFrame(root)
url_frame.pack(pady=10)

url_entry = ctk.CTkEntry(url_frame, width=500, placeholder_text="Enter URL here...")
url_entry.pack(side="left", padx=10)

check_btn = ctk.CTkButton(url_frame, text="Check URL", command=check_url)
check_btn.pack(side="left", padx=5)

paste_btn = ctk.CTkButton(url_frame, text="Paste URL", command=paste_clipboard)
paste_btn.pack(side="left", padx=5)

clear_btn = ctk.CTkButton(url_frame, text="Clear History", command=clear_history)
clear_btn.pack(side="left", padx=5)

# Result Label
result_label = ctk.CTkLabel(root, text="", font=("Arial", 16))
result_label.pack(pady=10)

# Risk Meter
risk_meter_label = ctk.CTkLabel(root, text="Phishing Risk Meter")
risk_meter_label.pack(pady=5)
risk_meter = ctk.CTkProgressBar(root, width=400)
risk_meter.pack(pady=5)
risk_meter.set(0)

# Panels for Detected Issues & Protection Tips
panel_frame = ctk.CTkFrame(root)
panel_frame.pack(pady=10, padx=20, fill="both", expand=True)

# Detected Issues
reason_frame = ctk.CTkFrame(panel_frame)
reason_frame.pack(side="left", fill="both", expand=True, padx=10, pady=10)
reason_label = ctk.CTkLabel(reason_frame, text="Detected Issues", font=("Arial", 14, "bold"))
reason_label.pack(pady=5)
reason_textbox = ctk.CTkTextbox(reason_frame, width=350, height=150)
reason_textbox.pack(fill="both", expand=True, pady=5)
reason_textbox.configure(state="disabled")

# Protection Tips
tips_frame = ctk.CTkFrame(panel_frame)
tips_frame.pack(side="right", fill="both", expand=True, padx=10, pady=10)
tips_label_header = ctk.CTkLabel(tips_frame, text="Protection Tips", font=("Arial", 14, "bold"))
tips_label_header.pack(pady=5)
tips_textbox = ctk.CTkTextbox(tips_frame, width=350, height=150)
tips_textbox.pack(fill="both", expand=True, pady=5)
tips_textbox.configure(state="disabled")

# History Label
history_label = ctk.CTkLabel(root, text="Checked URLs History", font=("Arial", 14, "bold"))
history_label.pack(pady=10)

# History Textbox
history_textbox = ctk.CTkTextbox(root, width=850, height=150)
history_textbox.pack(pady=5)
history_textbox.configure(state="disabled")

root.mainloop()
