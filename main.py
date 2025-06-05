import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import requests
import time
import threading
import os

API_KEY = 'fe859b7e3e45b05fd7abd192265c7535b0be6eba74922cfce7a5e0d7daad67c1'

def upload_file(file_path):
    url = 'https://www.virustotal.com/api/v3/files'
    headers = {'x-apikey': API_KEY}
    try:
        with open(file_path, 'rb') as f:
            files = {'file': (os.path.basename(file_path), f)}
            response = requests.post(url, files=files, headers=headers)
        if response.status_code == 200:
            return response.json()['data']['id']
    except Exception as e:
        print(f"Fayl yuborishda xatolik: {e}")
    return None

def upload_url(url_text):
    url = 'https://www.virustotal.com/api/v3/urls'
    headers = {'x-apikey': API_KEY}
    data = {'url': url_text}
    try:
        response = requests.post(url, headers=headers, data=data)
        if response.status_code == 200:
            return response.json()['data']['id']
    except Exception as e:
        print(f"URL yuborishda xatolik: {e}")
    return None

def get_report(scan_id):
    url = f'https://www.virustotal.com/api/v3/analyses/{scan_id}'
    headers = {'x-apikey': API_KEY}
    for _ in range(20):
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                if data['data']['attributes']['status'] == 'completed':
                    return data
        except Exception:
            pass
        time.sleep(5)
    return None

def get_overall_status(stats, scan_type):
    malicious = stats.get('malicious', 0)
    suspicious = stats.get('suspicious', 0)

    if malicious > 0:
        return f"❌ {scan_type.upper()} XAVFLI: Zararli faoliyat aniqlandi!"
    elif suspicious > 0:
        return f"⚠️ {scan_type.upper()} SHUBHALI: Shubhali faoliyat mavjud."
    else:
        return f"✅ {scan_type.upper()} XAVFSIZ: Hech qanday zararli belgi topilmadi."

def parse_report(report):
    stats = report['data']['attributes']['stats']
    results = report['data']['attributes']['results']

    summary = f"\n--- VirusTotal Hisoboti ---\n"
    summary += f"Umumiy antiviruslar soni: {len(results)}\n"
    summary += f"Zararli (malicious): {stats['malicious']}\n"
    summary += f"Shubhali (suspicious): {stats['suspicious']}\n"
    summary += f"Zararsiz (harmless): {stats['harmless']}\n\n"

    javob_bergan = []
    javob_bermagan = []

    for engine, result in results.items():
        category = result['category']
        res_text = result['result'] if result['result'] else "Toza"
        if category in ['malicious', 'suspicious', 'harmless', 'undetected']:
            javob_bergan.append(f"✅ {engine}: {res_text} ({category})")
        else:
            javob_bermagan.append(f"⏳ {engine}: javob bermagan")

    return summary, javob_bergan, javob_bermagan, stats

def select_file():
    file_path = filedialog.askopenfilename(title="Fayl tanlang", filetypes=[("Barcha fayllar", "*.*")])
    if file_path:
        entry_file.delete(0, tk.END)
        entry_file.insert(0, file_path)

def clear_url():
    entry_url.delete(0, tk.END)

def update_text(text):
    text_output.config(state=tk.NORMAL)
    text_output.delete(1.0, tk.END)
    text_output.insert(tk.END, text)
    text_output.config(state=tk.DISABLED)

def scan_worker(file_path, url_text):
    # Inputlarni darhol tozalash (threaddan tashqarida GUI orqali bajarish uchun root.after ishlatamiz)
    root.after(0, lambda: entry_file.delete(0, tk.END))
    root.after(0, lambda: entry_url.delete(0, tk.END))

    scan_type = None

    if file_path and os.path.exists(file_path):
        scan_type = "Fayl"
        root.after(0, lambda: update_text("📤 Fayl VirusTotal'ga yuborilmoqda...\n"))
        scan_id = upload_file(file_path)
    elif url_text.startswith("http://") or url_text.startswith("https://"):
        scan_type = "Havola"
        root.after(0, lambda: update_text("📤 URL VirusTotal'ga yuborilmoqda...\n"))
        scan_id = upload_url(url_text)
    else:
        root.after(0, lambda: messagebox.showwarning("⚠️ Xatolik", "Iltimos, to‘g‘ri fayl yoki URL kiriting."))
        return

    if not scan_id:
        root.after(0, lambda: messagebox.showerror("❗ Xatolik", "Yuborishda muammo yuz berdi. API kalitni tekshiring."))
        return

    root.after(0, lambda: update_text("⏳ Tekshiruv davom etmoqda...\n"))
    report = get_report(scan_id)

    if report:
        summary, javob_bergan, javob_bermagan, stats = parse_report(report)
        xulosa = get_overall_status(stats, scan_type)

        def insert_colored_text():
            text_output.config(state=tk.NORMAL)
            if "XAVFLI" in xulosa:
                text_output.insert(tk.END, xulosa + "\n\n", 'malicious')
            elif "SHUBHALI" in xulosa:
                text_output.insert(tk.END, xulosa + "\n\n", 'suspicious')
            else:
                text_output.insert(tk.END, xulosa + "\n\n", 'harmless')

            text_output.insert(tk.END, summary)
            text_output.insert(tk.END, "--- ✅ Javob bergan antiviruslar ---\n", 'harmless')
            for line in javob_bergan:
                if "malicious" in line.lower():
                    text_output.insert(tk.END, line + "\n", 'malicious')
                elif "suspicious" in line.lower():
                    text_output.insert(tk.END, line + "\n", 'suspicious')
                else:
                    text_output.insert(tk.END, line + "\n", 'harmless')

            text_output.insert(tk.END, "\n--- ⏳ Javob bermagan antiviruslar ---\n", 'info')
            for line in javob_bermagan:
                text_output.insert(tk.END, line + "\n", 'info')
            text_output.config(state=tk.DISABLED)

        root.after(0, insert_colored_text)
    else:
        root.after(0, lambda: text_output.insert(tk.END, "❗ Hisobot olishda xatolik yuz berdi.\n", 'malicious'))

def scan_file_or_url():
    file_path = entry_file.get().strip()
    url_text = entry_url.get().strip()
    threading.Thread(target=scan_worker, args=(file_path, url_text), daemon=True).start()

# GUI tuzish

root = tk.Tk()
root.title("🛡️ VirusTotal Skanner – Fayl va URL")
root.geometry("780x650")
root.resizable(False, False)

frame_top = tk.Frame(root)
frame_top.pack(pady=5)

tk.Label(frame_top, text="📂 Fayl manzili:", font=('Arial', 12)).grid(row=0, column=0, sticky='w')
entry_file = tk.Entry(frame_top, width=65, font=('Arial', 10))
entry_file.grid(row=1, column=0, columnspan=2, padx=5)

tk.Button(frame_top, text="📁 Tanlash", command=select_file, bg='#4CAF50', fg='white', width=10).grid(row=1, column=2, padx=2)

tk.Label(frame_top, text="🌐 URL manzili:", font=('Arial', 12)).grid(row=2, column=0, sticky='w', pady=(10, 0))
entry_url = tk.Entry(frame_top, width=80, font=('Arial', 10))
entry_url.grid(row=3, column=0, columnspan=3, padx=5, pady=2)

tk.Button(frame_top, text="❌ URL tozalash", command=clear_url, bg='#f44336', fg='white', width=15).grid(row=3, column=3)

tk.Button(root, text="🔎 TEKSHIRISH", command=scan_file_or_url, width=30, bg="#2196F3", fg="white", font=('Arial', 12, 'bold')).pack(pady=10)

text_output = scrolledtext.ScrolledText(root, width=95, height=25, font=('Consolas', 10))
text_output.pack(padx=10, pady=10)
text_output.config(state=tk.DISABLED)

text_output.tag_config('malicious', foreground='red')
text_output.tag_config('suspicious', foreground='orange')
text_output.tag_config('harmless', foreground='green')
text_output.tag_config('info', foreground='blue')

root.mainloop()

