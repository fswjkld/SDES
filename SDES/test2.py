import tkinter as tk
from tkinter import messagebox, StringVar
import random
from ASCII import SDES_ASCII
from SDES import SDES
import time
# 全局变量，存储SDES和SDES_ASCII对象
sdes = None
sdes_ascii = None

def generate_key():
    global sdes, sdes_ascii
    new_key = ''.join([str(random.randint(0, 1)) for _ in range(10)])
    sdes = SDES(new_key)
    sdes_ascii = SDES_ASCII(new_key)
    key_entry.set(new_key)

def on_key(event=None):
    key = key_entry.get()
    try:
        global sdes, sdes_ascii
        sdes = SDES(key)
        sdes_ascii = SDES_ASCII(key)
    except Exception as e:
        messagebox.showerror("Error", "Invalid key. Please enter a 10-bit binary key.")

def on_encrypt():
    plaintext = plaintext_entry.get()
    if use_ascii_var.get() == 1:
        if sdes_ascii is None:
            messagebox.showerror("Error", "SDES_ASCII object is not initialized. Please set a key first.")
            return
        encrypted = sdes_ascii.encrypt(plaintext)
    else:
        if sdes is None:
            messagebox.showerror("Error", "SDES object is not initialized. Please set a key first.")
            return
        encrypted = sdes.encrypt(plaintext)
    ciphertext_entry.set(encrypted)

def on_decrypt():
    ciphertext = ciphertext_entry.get()
    if use_ascii_var.get() == 1:
        if sdes_ascii is None:
            messagebox.showerror("Error", "SDES_ASCII object is not initialized. Please set a key first.")
            return
        decrypted = sdes_ascii.decrypt(ciphertext)
    else:
        if sdes is None:
            messagebox.showerror("Error", "SDES object is not initialized. Please set a key first.")
            return
        decrypted = sdes.decrypt(ciphertext)
    plaintext_entry.set(decrypted)

def brute_force_attack(ciphertext, expected_plaintext, ascii_mode):
    possible_keys = []

    start_time = time.time()

    for i in range(1024):
        key = bin(i)[2:].zfill(10)
        if ascii_mode:
            sdes = SDES_ASCII(key)
        else:
            sdes = SDES(key)
        decrypted_text = sdes.decrypt(ciphertext)

        if decrypted_text == expected_plaintext:
            possible_keys.append(key)

    end_time = time.time()
    elapsed_time = end_time - start_time

    result_window = tk.Toplevel(root)
    result_window.title("Brute Force Attack Results")
    result_window.geometry("500x320")

    frame = tk.Frame(result_window)
    frame.grid(row=0, column=0, sticky="nsew", padx=40, pady=10)
    result_window.grid_rowconfigure(0, weight=1)
    result_window.grid_columnconfigure(0, weight=1)

    result_text_widget = tk.Text(frame, height=15, width=50)
    result_text_widget.grid(row=0, column=0, sticky="nsew")
    frame.grid_rowconfigure(0, weight=1)
    frame.grid_columnconfigure(0, weight=1)

    for key in possible_keys:
        result_text_widget.insert(tk.END, f"Possible Key: {key}\n")

    result_text_widget.insert(tk.END, f"\nBrute force attack completed in: {elapsed_time:.2f} seconds")
    result_text_widget.config(state='disabled')
    test_button = tk.Button(frame, text="封闭测试",
                            command=lambda: test_keys(result_window, possible_keys, expected_plaintext, ciphertext,
                                                      ascii_mode))
    test_button.grid(row=1, column=0, sticky="ew", padx=10, pady=10)
    frame.grid_rowconfigure(1, weight=0)
def brute_force():
    ciphertext = ciphertext_entry.get()
    expected_plaintext = plaintext_entry.get()
    ascii_mode = use_ascii_var.get()
    brute_force_attack(ciphertext, expected_plaintext, ascii_mode)
def test_keys(window, possible_keys, plaintext, ciphertext, ascii_mode):
    test_window = tk.Toplevel(window)
    test_window.title("Test Keys")
    test_window.geometry("500x320")
    test_window.transient(window)  # 使新窗口为非模态
    test_window.grab_set()

    key_label = tk.Label(test_window, text="密钥:")
    key_label.grid(row=0, column=0, padx=10, pady=10)
    key_entry = tk.Entry(test_window, width=40)
    key_entry.grid(row=0, column=1, padx=10, pady=10)

    plaintext_label = tk.Label(test_window, text="明文:")
    plaintext_label.grid(row=1, column=0, padx=10, pady=10)
    plaintext_entry = tk.Entry(test_window, width=40)
    plaintext_entry.grid(row=1, column=1, padx=10, pady=10)

    ciphertext_label = tk.Label(test_window, text="密文:")
    ciphertext_label.grid(row=2, column=0, padx=10, pady=10)
    ciphertext_entry = tk.Entry(test_window, width=40)
    ciphertext_entry.grid(row=2, column=1, padx=10, pady=10)

    for key in possible_keys:
        sdes = SDES(key) if not ascii_mode else SDES_ASCII(key)
        encrypted = sdes.encrypt(plaintext)
        key_entry.delete(0, tk.END)
        key_entry.insert(0, key)
        plaintext_entry.delete(0, tk.END)
        plaintext_entry.insert(0, plaintext)
        ciphertext_entry.delete(0, tk.END)
        ciphertext_entry.insert(0, encrypted)
        test_window.update()
        time.sleep(1)

        if encrypted == ciphertext:
            messagebox.showinfo("Match Found", f"The encrypted text matches the expected ciphertext with key: {key}")
        else:
            messagebox.showinfo("Match Found", "wrong")

# 创建主窗口
root = tk.Tk()
root.title("S-DES Encryption/Decryption")
root.geometry("500x320")  # 设置窗口大小
top=tk.Label(root)
top.grid(row=0, column=0,padx=10, pady=15)
# 创建输入框和标签
key_label = tk.Label(root, text="密钥:")
key_label.grid(row=1, column=1, sticky="e", padx=5, pady=5)
key_entry = StringVar()
key_entry_var = tk.Entry(root, textvariable=key_entry, width=40)
key_entry_var.grid(row=1, column=2, sticky="ew", padx=5, pady=5)

plaintext_label = tk.Label(root, text="明文:")
plaintext_label.grid(row=2, column=1, sticky="e", padx=5, pady=5)
plaintext_entry = StringVar()
plaintext_entry_var = tk.Entry(root, textvariable=plaintext_entry, width=40)
plaintext_entry_var.grid(row=2, column=2, sticky="ew", padx=5, pady=5)

ciphertext_label = tk.Label(root, text="密文:")
ciphertext_label.grid(row=3, column=1, sticky="e", padx=5, pady=5)
ciphertext_entry = StringVar()
ciphertext_entry_var = tk.Entry(root, textvariable=ciphertext_entry, width=40)
ciphertext_entry_var.grid(row=3, column=2, sticky="ew", padx=5, pady=5)

# 添加ASCII模式复选框
use_ascii_var = tk.IntVar()
use_ascii_checkbox = tk.Checkbutton(root, text="使用ASCII模式", variable=use_ascii_var)
use_ascii_checkbox.grid(row=4, column=3, sticky="e", padx=10, pady=10)

# 创建按钮
generate_button = tk.Button(root, text="随机生成密钥", command=generate_key)
generate_button.grid(row=1, column=3, padx=20, pady=10, sticky='e')
encrypt_button = tk.Button(root, text="加密", command=on_encrypt)
encrypt_button.grid(row=2, column=3, padx=40, pady=10, sticky="e")
decrypt_button = tk.Button(root, text="解密", command=on_decrypt)
decrypt_button.grid(row=3, column=3, padx=40, pady=10, sticky="e")
brute_force_button = tk.Button(root, text="暴力破解", command=brute_force)
brute_force_button.grid(row=4, column=2, padx=40, pady=10, sticky='ew')

# 绑定事件，当密钥文本框内容发生变化时调用on_key函数
key_entry_var.bind("<Leave>", on_key)

# 运行主循环
root.mainloop()


