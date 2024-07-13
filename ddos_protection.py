import sys
import socket
import signal
from os import kill, getpid, name, system, remove
from time import sleep
from threading import Thread
from random import choice
from urllib.parse import unquote
from subprocess import Popen, PIPE, DEVNULL
import pexpect

# Import configuration variables at the module level
try:
    from config import (
        host_fake, host_real, port_fake, port_real, max_speed_user, max_speed_server,
        timeout_conn, reset_send_data_user, max_conn, max_data_user, block_on_count,
        reset_on_time, is_get_sock, ban_sock, headers, ban_ip, force_firewall_count,
        block_time, time_connect
    )
except ImportError:
    print("[CONFIG_ERR]>> config.py not found or syntax error!")
    input()
    sys.exit()

class DDoSProtection:
    def __init__(self):
        self.pid = getpid()
        self.ddos = {}
        self.block = []
        self.blockks = []
        self.force_block = {}
        self.run_flag = True
        self.time_count = 0
        self.count_conn = 0
        self.all_conn = []
        self.soc = None
        self.load_config()
        self.byte_send_user = int((self.max_speed_user * 1024 * 1024) / 70)
        self.time_send_user = 1 / 1000
        self.byte_send_server = int((self.max_speed_server * 1024 * 1024) / 70)
        self.time_send_server = 1 / 1000

    def load_config(self):
        try:
            ########################################################
            self.host_fake = host_fake
            self.host_real = host_real
            self.port_fake = port_fake
            self.port_real = port_real
            self.max_speed_user = max_speed_user
            self.max_speed_server = max_speed_server
            self.timeout_conn = timeout_conn
            self.reset_send_data_user = reset_send_data_user
            self.max_conn = max_conn
            self.max_data_user = max_data_user
            self.block_on_count = block_on_count
            self.reset_on_time = reset_on_time
            self.is_get_sock = is_get_sock
            self.ban_sock = ban_sock
            self.headers = headers
            self.ban_ip = ban_ip
            self.list_ban_ip = str(ban_ip).replace("/32", "")
            self.force_firewall_count = force_firewall_count
            self.block_time = block_time
            self.time_connect = time_connect
            #########################################################
            
            for ip in [self.host_fake, self.host_real]:
                if not isinstance(ip, str) or not all(0 <= int(part) < 256 for part in ip.split('.')):
                    raise ValueError(f"Invalid IP address: {ip}")
            for port in [self.port_fake, self.port_real]:
                if not isinstance(port, int) or not (1 <= port <= 65535):
                    raise ValueError(f"Invalid port: {port}")
            if not isinstance(self.max_speed_user, int) or self.max_speed_user < 0:
                raise ValueError("max_speed_user should be a non-negative integer")
            if not isinstance(self.max_speed_server, int) or self.max_speed_server < 0:
                raise ValueError("max_speed_server should be a non-negative integer")
            if not isinstance(self.timeout_conn, int) or self.timeout_conn < 1:
                raise ValueError("timeout_conn should be at least 1")
            if not isinstance(self.reset_send_data_user, int) or self.reset_send_data_user < 0:
                raise ValueError("reset_send_data_user should be a non-negative integer")
            if not isinstance(self.max_conn, int) or self.max_conn < 1:
                raise ValueError("max_conn should be at least 1")
            if not isinstance(self.max_data_user, int) or self.max_data_user < 0:
                raise ValueError("max_data_user should be a non-negative integer")
            if not isinstance(self.block_on_count, int) or self.block_on_count < 1:
                raise ValueError("block_on_count should be at least 1")
            if not isinstance(self.reset_on_time, int) or self.reset_on_time < 1:
                raise ValueError("reset_on_time should be at least 1")
            if not isinstance(self.is_get_sock, int) or self.is_get_sock not in [0, 1]:
                raise ValueError("is_get_sock should be either 0 or 1")
            if not isinstance(self.force_firewall_count, int) or self.force_firewall_count < 0:
                raise ValueError("force_firewall_count should be a non-negative integer")
            if not isinstance(self.block_time, int) or self.block_time < 0:
                raise ValueError("block_time should be a non-negative integer")
            if not isinstance(self.time_connect, (int, float)) or self.time_connect < 0:
                raise ValueError("time_connect should be a non-negative number")

        except ValueError as e:
            print(f"[CONFIG_ERR]>> {e}")
            input()
            sys.exit()

    def time_run(self):
        while True:
            sleep(1)
            self.time_count += 1

    def block_with_time(self, ip, time, is_add=1):
        password = "idk"  # Linux password
        command_remove = f"sudo iptables -D INPUT -s {ip} -j DROP"
        command_add = f"sudo iptables -A INPUT -s {ip} -j DROP"
        if is_add == 1:
            self.block.append(ip)
        child = pexpect.spawn(command_add)
        child.expect("password for")
        child.sendline(password)
        child.expect(pexpect.EOF)
        print(f'[INFO_TIMEBLOCK] {ip} DROPPED caused by exceeding threshold')
        while self.time_count <= time:
            sleep(1)
        while ip in self.block:
            child = pexpect.spawn(command_remove)
            child.expect("password for")
            child.sendline(password)
            child.expect(pexpect.EOF)
            self.block.remove(ip)
            print(f'[INFO_TIMEBLOCK] {ip} UNDROPPED - by expired {self.block_time} minutes')
        print("Unblock: {} (Out of time)".format(ip))

    def kill_process(self):
        print(f"\n[INFO_SYS] Closing process....")
        if hasattr(signal, 'SIGKILL'):
            kill(self.pid, signal.SIGKILL)
        else:
            kill(self.pid, signal.SIGABRT)
        sys.exit()

    def clear(self):
        system("clear")

    def forward(self, ip, port, source, destination, is_a, is_user_send, b=""):
        if is_a == 1:
            byte_s = int(self.byte_send_user)
            time_s = float(self.time_send_user)
        else:
            byte_s = int(self.byte_send_server)
            time_s = float(self.time_send_server)
        if byte_s == 0:
            byte_s = 65535
            time_s = 0
        len_data = -1
        if self.reset_send_data_user != 0:
            time = self.time_count + (self.reset_send_data_user * 60)
        else:
            time = -1
        try:
            string = " "
            while string:
                if len_data < self.max_data_user:
                    string = source.recv(byte_s)
                    if string:
                        if self.max_data_user > 0 and is_user_send == 0:
                            len_data += len(string)
                        destination.sendall(string)
                    else:
                        source.shutdown(socket.SHUT_RD)
                        destination.shutdown(socket.SHUT_WR)
                    sleep(time_s)
                else:
                    print("[FORWARD_INFO] Out of data on {} min: Port {} from {} ({} byte)".format(self.reset_send_data_user, port, ip, self.max_data_user))
                    self.block.append(ip)
                    self.block_ip(ip, source)
                    break
                if time == -1:
                    continue
                elif self.time_count > time and self.max_data_user > 0:
                    time = self.time_count + (self.reset_send_data_user * 60)
                    len_data = 0
        except TimeoutError:
            print("[INFO_ERR]>> Timeout: Port {} from {}".format(str(port), str(ip)))
        except ConnectionAbortedError:
            print("[INFO_ERR]>> Aborted connection: Port {} from {}".format(str(port), str(ip)))
        except ConnectionResetError:
            print("[INFO_ERR]>> Close connection: Port {} from {}".format(str(port), str(ip)))
        except ConnectionRefusedError:
            print("[INFO_ERR]>> Connection refused: Port {} from {}".format(str(port), str(ip)))
        except:
            pass
        if is_a == 1:
            self.count_conn -= 1
            for i in [s for s in self.all_conn if "conn_{}:{}".format(ip, b) in s]:
                try:
                    self.all_conn.remove(i)
                except:
                    pass
            del globals()["conn_" + str(ip) + ":" + str(b)]
        try:
            source.shutdown(socket.SHUT_RD)
            destination.shutdown(socket.SHUT_WR)
        except:
            return

    def close_conn(self):
        try:
            self.soc.close()
        except:
            pass
        for i in self.all_conn:
            try:
                print(i)
            except:
                pass

    def block_ip(self, con_ip, a):
        self.force_block[con_ip] = 0
        if self.block_time != 0:
            print("[INFO_BLOCK] Block {} for {} minutes".format(con_ip, self.block_time))
            Thread(target=self.block_with_time, args=(con_ip, self.time_count + (self.block_time * 60), 0)).start()
        print("[INFO_BLOCK] Close all connection from {}".format(con_ip))
        try:
            a.close()
        except:
            pass
        for i in [d for d in self.all_conn if "conn_{}:".format(con_ip) in d]:
            try:
                self.all_conn.remove(i)
            except:
                pass
            try:
                globals()[i].close()
            except:
                pass

    def open_port(self, port):
        current_conn = []
        self.all_conn = []
        count = 0
        self.count_conn = 0
        self.soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.soc.bind((str(self.host_fake), int(port)))
            self.soc.listen(9)
            Thread(target=self.time_run, args=()).start()
            print("[!!] >> Started! Anti-DDoS protection")
            while True:
                try:
                    a, b = self.soc.accept()
                    if b[0] in self.block:
                        a.close()
                        if self.force_firewall_count > 0:
                            try:
                                self.force_block[b[0]] += 1
                            except:
                                self.force_block[b[0]] = 1
                            if self.force_block[b[0]] > self.force_firewall_count:
                                print("!! Detected {0} try request {1} times! Blocking...".format(str(b[0]), str(self.force_block[self.count_ip])))
                                Thread(target=self.block_ip, args=(b[0], a)).start()
                                self.force_block[b[0]] = 0
                                continue
                            print("Blocked connection from {0} ({1})".format(b[0], self.force_block[b[0]]))
                        else:
                            print("Blocking connection from {0}".format(b[0]))
                    else:
                        if self.count_conn <= self.max_conn or b[0] in current_conn:
                            try:
                                self.ddos[b[0]] += 1
                            except KeyError:
                                self.ddos[b[0]] = 1
                            try:
                                if self.ddos[b[0]] > self.block_on_count:
                                    print("!! Detected DDOS from {}! Blocking...".format(b[0]))
                                    self.block.append(b[0])
                                    Thread(target=self.block_ip, args=(b[0], a)).start()
                                    continue
                            except:
                                self.ddos[b[0]] = 1
                            if b[0] not in current_conn:
                                self.count_conn += 1
                                is_a = 1
                            else:
                                is_a = 0
                            current_conn.append(b[0])
                            self.all_conn.append("conn_" + str(b[0]) + ":" + str(b[1]))
                            globals()["conn_" + str(b[0]) + ":" + str(b[1])] = a
                            count += 1
                            print(f"{count}. Port {port} -> {self.port_real} | Accept: {b[0]} ({self.ddos[b[0]]})")
                            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            server_socket.settimeout(5)
                            server_socket.connect((str(self.host_real), int(self.port_real)))
                            server_socket.settimeout(self.timeout_conn)
                            a.settimeout(self.timeout_conn)
                            Thread(target=self.forward, args=(b[0], port, a, server_socket, 1, is_a, b[1])).start()
                            Thread(target=self.forward, args=(b[0], port, server_socket, a, 0, 0)).start()
                        else:
                            print("Full connection {}".format(b[0]))
                            a.close()
                    sleep(float(self.time_connect))
                except OSError as e:
                    if '[closed]' not in str(self.soc):
                        print(f"ERROR: Port {port} | {e}")
                        a.close()
                        continue
                    break
                except:
                    continue
        except PermissionError:
            print(f"ERROR: Port {port} cannot be spoof! Need administrator permission!!")
            return
        except OSError as e:
            print(f"ERROR: Port {port} | {e}")
            return

    def about(self):
        while True:
            self.clear()
            a = str(input("[ABOUT_INFO] About this program\n\n1. Github\n2. Readme\n0. Back\n\n >> Your choose: "))
            if a == "1":
                system("start \"\" \"https://github.com/iFanpSGTS\"")
            elif a == "2":
                self.clear()
                print("This program is fully rewrite by iFanpSGTS, and also big credit \
for https://github.com/KhanhNguyen9872/Anti-DDOS_Win.\nThis program code is basically from his github \
but rewrited by iFanpSGTS")
                input()
                break
            elif a == "0":
                break

    def run_program(self):
        while 1:
            proxy_status = self.get_proxy_status()
            self.clear()
            if proxy_status == "Not found":
                print("[INFO_START] Program is running!\tProxy banned status: {}\nChoose option\n1. Anti-DDOS [Fake Port {}]\n2. About\n3. Load/Download proxy (for better prevention)\n0. Exit\n\n".format(proxy_status, str(self.port_fake)))
            else:
                print("[INFO_START] Program is running!\tProxy banned status: {}\nChoose option\n1. Anti-DDOS [Fake Port {}]\n2. About\n0. Exit\n\n".format(proxy_status, str(self.port_fake)))
            ask = str(input(">> Your choose: "))
            if ask == "1":
                self.start(self.port_fake)
            elif ask == "2":
                self.about()
            elif ask == "3" and proxy_status == "Not found":
                self.load_proxy()
            elif ask == "0":
                self.kill_process()
            continue

    def start(self, port):
        self.clear()
        print("\n[RUNNING ON] config fake: http://{0}:{1} -> http://{2}:{3}".format(str(self.host_fake), str(self.port_fake), str(self.host_real), str(self.port_real)))
        print(f"[/] >> Starting Anti-DDOS...")
        Thread(target=self.open_port, args=(port,)).start()
        sleep(2)
        while True:
            try:
                print("[/] No DDOS in {} seconds, reset count...".format(str(self.reset_on_time)))
                self.ddos = {}
                sleep(float(self.reset_on_time))
            except KeyboardInterrupt:
                print("[INFO_CON_STOP] Stopping all connection.... on start")
                self.kill_process()
                self.close_conn()

    def load_proxy(self):
        if int(self.is_get_sock) == 1:
            import urllib.request, ssl
            self.clear()
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            print("[/] Downloading Sock Proxy....")
            total_ip = 0
            for sock in self.ban_sock:
                count_ip = 0
                print("GET: {}".format(sock), end=" ")
                sys.stdout.flush()
                req = urllib.request.Request(sock, headers={'User-Agent': choice(self.headers)})
                try:
                    https_handler = urllib.request.HTTPSHandler(context=ssl_context)
                    opener = urllib.request.build_opener(https_handler)
                    response = opener.open(req, timeout=20)
                    if response.getcode() == 200:
                        ips = response.read().decode().replace('\r', '').split('\n')
                        for ip in ips:
                            try:
                                temp = str(ip.split(':')[0])
                                int("".join(temp.split(".")))
                                if ip and len(temp.split(".")) == 4:
                                    self.blockks.append(temp)
                                    count_ip += 1
                            except:
                                continue
                        print("[PROXY_GET_STATUS] (OK - {} IP)".format(str(count_ip)))
                        total_ip += count_ip
                    else:
                        print("[PROXY_GET_STATUS] (DIED)")
                except Exception as e:
                    print(f"[PROXY_GET_STATUS] (ERR - {e})")
                except urllib.error.URLError as e:
                    print("[PROXY_GET_STATUS] (DIED - {})".format(str(e.reason)))
                except TimeoutError:
                    pass
                except:
                    pass
            self.blockks = list(set(self.blockks))
            print("\n[PROXY_FOUND] Total IP Sock: {} IP".format(str(total_ip)))
            print("[PROXY_FOUND] Real IP Sock: {} IP".format(str(len(self.blockks))))
            asks = str(input("\n[PROXY_FOUND] NOTE: Y for save to file, N for skip save\n>> Do you want to save Real IP? [Y/N]: "))
            while True:
                if asks == "Y" or asks == "y":
                    with open("proxy.txt", "w") as f:
                        f.write("blockk={}".format(str(self.blockks)))
                    break
                elif asks == "N" or asks == "n":
                    remove("proxy.txt")
                    break
        print("[PROXY_FOUND] Processing IP....")
        for _ in self.blockks:
            self.block.append(str(_))
            # del self.blockks
        self.block = list(set(self.block))

    def get_proxy_status(self):
        try:
            with open("proxy.txt", "r") as f:
                exec("global blockk; {}".format(f.read()))
                return f"{str(len(blockk))} IP"
        except:
            return "Not found"

if __name__ == "__main__":
    ddos_protection = DDoSProtection()
    ddos_protection.clear()
    print("[INFO_WARN] Warning: This tool only Anti-DDOS TCP Port, please block all UDP Port, because your server may be UDPFlood!\n")
    input("[##] Press Enter to continue! ")
    try:
        ddos_protection.run_program()
    except KeyboardInterrupt:
        print("[##] Stopping all connection....")
        ddos_protection.close_conn()
        ddos_protection.kill_process()
