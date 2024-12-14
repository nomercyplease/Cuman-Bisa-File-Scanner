import hashlib
import requests
from time import sleep
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import threading
from matplotlib import cm  # Import colormap untuk warna menarik

try:
    from key import API_KEY
except ImportError:
    API_KEY = "2e291fdc15f0c55c450f9b6d690ea1b68ccdfbf14efa9df3246cc6ab1c599e5e"

HEADERS = {"x-apikey": API_KEY}

def hash_it(file, algorithm):
    hasher = hashlib.new(algorithm)
    with open(file, 'rb') as f:
        hasher.update(f.read())
    return hasher.hexdigest()

def vt_get_data(f_hash):
    url = f"https://www.virustotal.com/api/v3/files/{f_hash}"
    while True:
        response = requests.get(url, headers=HEADERS)
        if error_handle(response):
            break
    return response

def vt_post_files(file, url="https://www.virustotal.com/api/v3/files"):
    with open(file, "rb") as f:
        file_bin = f.read()
    upload_package = {"file": (file.name, file_bin)}
    while True:
        response = requests.post(url, headers=HEADERS, files=upload_package)
        if error_handle(response):
            break
    return response

def vt_get_analyses(response):
    _id = response.json().get("data").get("id")
    url = f"https://www.virustotal.com/api/v3/analyses/{_id}"
    while True:
        sleep(15)
        while True:
            response = requests.get(url, headers=HEADERS)
            if error_handle(response):
                break
        if response.json().get("data").get("attributes").get("status") == "completed":
            f_hash = response.json().get("meta").get("file_info").get("sha256")
            return f_hash

def error_handle(response):
    if response.status_code == 429:
        sleep(60)
    if response.status_code == 401:
        raise Exception("Invalid API key")
    elif response.status_code not in (200, 404, 429):
        raise Exception(response.status_code)
    else:
        return True

def parse_response(response):
    json_obj = response.json().get("data").get("attributes")
    output = {
        "name": json_obj.get("meaningful_name"),
        "stats": json_obj.get("last_analysis_stats"),
        "votes": json_obj.get("total_votes"),
        "hash": {
            "sha1": json_obj.get("sha1"),
            "sha256": json_obj.get("sha256")
        },
        "size": json_obj.get("size"),
        "results": json_obj.get("last_analysis_results")
    }
    return output

def scan_file(file_path, table, chart_frame, result_frame):
    try:
        f_hash = hash_it(file_path, "sha256")
        response = vt_get_data(f_hash)
        if response.status_code == 404:
            response = vt_get_data(vt_get_analyses(vt_post_files(file_path)))

        if response.status_code == 200:
            parsed_response = parse_response(response)
            update_table(parsed_response, table)
            update_chart(parsed_response, chart_frame)
            update_results(parsed_response, result_frame)
        else:
            messagebox.showerror("Error", f"Unexpected status code: {response.status_code}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def update_table(data, table):
    table.delete(*table.get_children())
    table.insert("", "end", values=("Name", data["name"]))
    table.insert("", "end", values=("Size", f"{data['size']} bytes"))
    table.insert("", "end", values=("SHA-256", data["hash"]["sha256"]))
    table.insert("", "end", values=("Undetected", data["stats"]["undetected"]))
    table.insert("", "end", values=("Detected", data["stats"]["malicious"]))


def update_chart(data, frame):
    for widget in frame.winfo_children():
        widget.destroy()

    stats = data["stats"]
    labels = ["Malicious", "Suspicious", "Undetected", "Timeout", "Failure"]  # Nama label lebih deskriptif
    sizes = [
        stats.get("malicious", 0),
        stats.get("suspicious", 0),
        stats.get("undetected", 0),
        stats.get("timeout", 0),
        stats.get("failure", 0)
    ]
    colors = ['#dc143c', '#ffc107', '#28a745', '#6c757d', '#17a2b8']  # Warna kustom # Pilih warna yang lebih menarik dari colormap

    # Filter hanya data yang memiliki nilai > 0
    filtered_labels, filtered_sizes, filtered_colors = zip(
        *[(label, size, color) for label, size, color in zip(labels, sizes, colors) if size > 0]
    )

    fig = Figure(figsize=(5, 5))
    ax = fig.add_subplot(111)
    wedges, texts, autotexts = ax.pie(
        filtered_sizes, labels=filtered_labels, autopct='%1.1f%%',
        startangle=140, colors=filtered_colors, wedgeprops=dict(width=0.3)
    )

    # Tambahkan Judul
    ax.set_title("Community Score Analysis", fontsize=12, fontweight='bold')

    # Tambahkan Legenda
    ax.legend(wedges, filtered_labels, title="Categories", loc="best")

    # Render grafik di tkinter
    canvas = FigureCanvasTkAgg(fig, master=frame)
    canvas.draw()
    canvas.get_tk_widget().pack()


def update_results(data, frame):
    for widget in frame.winfo_children():
        widget.destroy()

    canvas = tk.Canvas(frame)
    scrollbar = ttk.Scrollbar(frame, orient="vertical", command=canvas.yview)
    scrollable_frame = tk.Frame(canvas)

    scrollable_frame.bind(
        "<Configure>",
        lambda e: canvas.configure(
            scrollregion=canvas.bbox("all")
        )
    )

    canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set)

    tk.Label(scrollable_frame, text="Security Vendor Analysis", font=("Arial", 12, "bold")).pack(anchor="center")
    table_frame = tk.Frame(scrollable_frame)
    table_frame.pack(fill="both", expand=True)

    # Menambahkan Treeview
    table = ttk.Treeview(table_frame, columns=("Vendor", "Result"), show="headings")
    table.heading("Vendor", text="Vendor")
    table.heading("Result", text="Result")

    # Atur ukuran kolom (lebar)
    table.column("Vendor", anchor="w", stretch=True, width=500)  # Lebar kolom Vendor
    table.column("Result", anchor="center", stretch=True, width=450)  # Lebar kolom Result

    table.pack(fill="both", expand=True)
    

    for vendor, analysis in data["results"].items():
        result_text = analysis['result'] if analysis['result'] else "Undetected"
        table.insert("", "end", values=(vendor, result_text))

    tk.Label(scrollable_frame, text="Community Score", font=("Arial", 12, "bold")).pack(anchor="w")
    community_score = data["votes"]
    positives = community_score.get("harmless", 0)
    negatives = community_score.get("malicious", 0)
    tk.Label(scrollable_frame, text=f"Harmless: {positives} • Malicious: {negatives}", fg="blue", anchor="w").pack(fill="x")

    canvas.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")


def start_scan(file_path, table, chart_frame, result_frame, status_label):
    def _scan():
        status_label.config(text="Scanning... Please wait.")
        scan_file(file_path, table, chart_frame, result_frame)
        status_label.config(text="Scan complete.")

    threading.Thread(target=_scan, daemon=True).start()

def main():
    root = tk.Tk()
    root.title("Cuman Bisa File Scanner")
    root.geometry("1200x800")  # Adjusted size for better layout

    # Menambahkan ikon di title bar
    try:
        root.iconbitmap("alien-icon-png-23.ico")  # Ganti "logo.ico" dengan path ke file ikon Anda
    except Exception as e:
        print(f"Error setting icon: {e}")


    frame = tk.Frame(root)
    frame.pack(pady=20, padx=20, fill="x")

    file_path_var = tk.StringVar()

    tk.Label(frame, text="Select a file to scan:").pack(anchor="w")
    file_entry = ttk.Entry(frame, textvariable=file_path_var, width=60)
    file_entry.pack(side="left", padx=5, pady=5)

    def browse_file():
        file_path = filedialog.askopenfilename()
        file_path_var.set(file_path)

    ttk.Button(frame, text="Browse", command=browse_file).pack(side="left")

    status_label = tk.Label(frame, text="Idle.", anchor="w")
    status_label.pack(fill="x", pady=5)

    # Create a frame for the table and charts to sit side by side
    analysis_frame = tk.Frame(root)
    analysis_frame.pack(fill="both", expand=True, pady=10)

    # Table frame
    table_frame = tk.Frame(analysis_frame)
    table_frame.pack(side="left", fill="both", expand=True, padx=10)

    columns = ("Attribute", "Value")
    table = ttk.Treeview(table_frame, columns=columns, show="headings")
    table.heading("Attribute", text="Attribute")
    table.heading("Value", text="Value")
    table.pack(fill="both", expand=True)

    # Chart and result frame
    chart_result_frame = tk.Frame(analysis_frame)
    chart_result_frame.pack(side="left", fill="both", expand=True, padx=10)

    # Chart frame
    chart_frame = tk.Frame(chart_result_frame)
    chart_frame.pack(fill="both", expand=True)

    # Result frame
    result_frame = tk.Frame(chart_result_frame)
    result_frame.pack(fill="both", expand=True, pady=10)

    def scan():
        file_path = file_path_var.get()
        if not Path(file_path).exists():
            messagebox.showerror("Error", "File not found.")
        else:
            start_scan(file_path, table, chart_frame, result_frame, status_label)

    ttk.Button(root, text="Scan", command=scan).pack(pady=10)

    root.mainloop()

def vt_post_files(file, url="https://www.virustotal.com/api/v3/files"):
    with open(file, "rb") as f:
        file_bin = f.read()
    file_name = Path(file).name  # Ambil nama file dari path
    upload_package = {"file": (file_name, file_bin)}  # Gunakan nama file yang benar
    while True:
        response = requests.post(url, headers=HEADERS, files=upload_package)
        if error_handle(response):
            break
    return response

if __name__ == "__main__":
    main()
