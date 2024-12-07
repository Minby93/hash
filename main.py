import tkinter as tk
from tkinter import ttk, messagebox
from tkinter.scrolledtext import ScrolledText


def pad(data: bytes) -> bytes:
    padding_len = 8 - (len(data) % 8)
    return data + bytes([padding_len] * padding_len)

def hash_message_gost(message: bytes, key: bytes, block_size: int = 8) -> bytes:
    message = pad(message)
    blocks = [message[i:i + block_size] for i in range(0, len(message), block_size)]
    h_prev = bytes([0] * block_size)
    # H(i) = E(H(i-1))(M(i)) ^ M(i)
    for block in blocks:
        encrypted = gost_encrypt_block(h_prev, key)
        intermediate = int.from_bytes(encrypted, 'little') ^ int.from_bytes(block, 'little')
        h_prev = intermediate.to_bytes(block_size, 'little')
    return h_prev

def gost_encrypt_block(block: bytes, key: bytes) -> bytes:
    left = int.from_bytes(block[:4], byteorder='little')
    right = int.from_bytes(block[4:], byteorder='little')
    key_parts = [int.from_bytes(key[i:i+4], byteorder='little') for i in range(0, 32, 4)]
    for i in range(24):
        right, left = gost_round(left, right, key_parts[i % 8])
    for i in range(8):
        right, left = gost_round(left, right, key_parts[7 - i])
    return left.to_bytes(4, byteorder='little') + right.to_bytes(4, byteorder='little')

def gost_round(left: int, right: int, key: int) -> (int, int):
    temp = (left + key) % (2 ** 32)
    temp = substitute(temp)
    temp = rol(temp, 11)
    new_right = right ^ temp
    return new_right, left

def substitute(value: int) -> int:

    return value

def rol(value: int, shift: int) -> int:
    return ((value << shift) & 0xFFFFFFFF) | (value >> (32 - shift))


def hash_action():
    message = input_message.get("1.0", tk.END).strip().encode()
    key = input_key.get().encode()

    if len(key) != 32:
        messagebox.showerror("Ошибка", "Ключ должен быть длиной 32 байта!")
        return

    try:
        result = hash_message_gost(message, key).hex()
        output_result.delete("1.0", tk.END)
        output_result.insert(tk.END, result)
    except Exception as e:
        messagebox.showerror("Ошибка", f"Произошла ошибка: {e}")


root = tk.Tk()
root.title("Хэширование по ГОСТ")


ttk.Label(root, text="Сообщение:").pack(anchor=tk.W, padx=10, pady=5)
input_message = ScrolledText(root, height=5, width=50)
input_message.pack(padx=10, pady=5)


ttk.Label(root, text="Ключ (32 байта):").pack(anchor=tk.W, padx=10, pady=5)
input_key = ttk.Entry(root, width=50)
input_key.pack(padx=10, pady=5)


ttk.Button(root, text="Хэшировать", command=hash_action).pack(padx=10, pady=10)

ttk.Label(root, text="Хэш (результат):").pack(anchor=tk.W, padx=10, pady=5)
output_result = ScrolledText(root, height=5, width=50)
output_result.pack(padx=10, pady=5)

root.mainloop()
