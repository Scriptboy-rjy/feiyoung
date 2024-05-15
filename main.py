import os
import tkinter as tk
from tkinter import messagebox
from scapy.all import sniff, AsyncSniffer
import threading
from datetime import datetime
import psutil

class PacketSniffer:
    def __init__(self, interface, filter_string, output_dir):
        self.interface = interface
        self.filter_string = filter_string
        self.output_dir = output_dir
        self.sniffer = None

        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

        # 开始抓包时覆盖写 output.txt
        open(os.path.join(self.output_dir, 'output.txt'), 'w').close()

    def packet_callback(self, packet):
        if self.filter_string in str(packet):
            with open(os.path.join(self.output_dir, 'output.txt'), 'a') as f:
                f.write(packet.show(dump=True) + '\n\n')
            self.stop_sniffing()

    def start_sniffing(self):
        self.sniffer = AsyncSniffer(iface=self.interface, prn=self.packet_callback)
        self.sniffer.start()

    def stop_sniffing(self):
        if self.sniffer:
            self.sniffer.stop()

class App:
    def __init__(self, root, sniffer):
        self.root = root
        self.sniffer = sniffer
        self.is_sniffing = False

        self.start_button = tk.Button(root, text="开始抓包", command=self.start_sniffing)
        self.start_button.pack(pady=10)

    def start_sniffing(self):
        if not self.is_sniffing:
            self.sniffer_thread = threading.Thread(target=self.sniffer.start_sniffing)
            self.sniffer_thread.start()
            self.is_sniffing = True
            self.start_button.config(state=tk.DISABLED)
            messagebox.showinfo("信息", "抓包已开始")
            threading.Thread(target=self.wait_for_packet).start()

    def wait_for_packet(self):
        self.sniffer.sniffer.join()  # Wait until the sniffer stops
        self.extract_account_password()
        self.root.quit()

    def extract_account_password(self):
        try:
            desktop_path = os.path.join(os.path.join(os.environ['USERPROFILE']), 'Desktop')
            output_file_path = os.path.join(self.sniffer.output_dir, 'output.txt')
            account_passwords_file_path = os.path.join(desktop_path, 'account_passwords.txt')

            if not os.path.exists(output_file_path):
                messagebox.showwarning("警告", "output.txt 文件不存在")
                return

            with open(output_file_path, 'r') as f:
                lines = f.readlines()

            accounts_passwords = []
            username, password = None, None

            for line in lines:
                if "username  = '" in line:
                    start_index = line.find("username  = '") + len("username  = '")
                    end_index = line.find("'", start_index)
                    username = line[start_index:end_index]

                if "password  = '" in line:
                    start_index = line.find("password  = '") + len("password  = '")
                    end_index = line.find("'", start_index)
                    password = line[start_index:end_index]

                if username and password:
                    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    accounts_passwords.append(f"{timestamp} - Username: {username}, Password: {password}")
                    username, password = None, None  # Reset for next pair

            if accounts_passwords:
                with open(account_passwords_file_path, 'a') as f:
                    for entry in accounts_passwords:
                        f.write(entry + '\n')
                messagebox.showinfo("信息", f"账号和密码已输出到 {account_passwords_file_path}")
            else:
                messagebox.showinfo("信息", "未找到任何账号和密码")

        except Exception as e:
            messagebox.showerror("错误", f"输出账号和密码时发生错误: {e}")

def get_ethernet_interface():
    interfaces = psutil.net_if_addrs()
    for interface in interfaces:
        if "Ethernet" in interface or "以太网" in interface:
            return interface
    raise Exception("未找到以太网接口")

if __name__ == "__main__":
    root = tk.Tk()
    root.title("抓包程序")
    root.geometry("400x300")

    interface = get_ethernet_interface()  # 自动获取以太网接口名称
    filter_string = "password"
    output_dir = "C:/output"

    sniffer = PacketSniffer(interface, filter_string, output_dir)
    app = App(root, sniffer)

    root.mainloop()
