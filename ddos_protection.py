if (__name__ == "__main__"):
    import sys
    def time_run():
        global time_count
        time_count=0
        while 1:
            sleep(1)
            time_count+=1
            
    def block_with_time(ip,time,is_add=1):
        global block,time_count
        if is_add==1:
            block.append(ip)
        system(f"sudo iptables -A INPUT -s {ip} -j DROP".format(ip))
        print(f'[INFO_TIMEBLOCK] {ip} DROPPED caused by exceeding threshold')
        while time_count<=time:
            sleep(1)
        while ip in block:
            system(f"sudo iptables -D INPUT -s {ip} -j DROP")
            block.remove(ip)
            print(f'[INFO_TIMEBLOCK] {ip} UNDROPPED - by expired {block_time} minutes')
        print("Unblock: {} (Out of time)".format(ip))
        return
    
    def kill_process():
        print(f"\n[INFO_SYS] Closing process....")
        if hasattr(signal, 'SIGKILL'):
            kill(pid, signal.SIGKILL)
        else:
            kill(pid, signal.SIGABRT)
        sys.exit()
        
    def clear():
        system("cls")
        
    def forward(ip,port,source,destination,is_a,is_user_send,b=""):
        global time_count,block
        if is_a==1:
            byte_s=int(globals()["byte_send_user"])
            time_s=float(globals()["time_send_user"])
        else:
            byte_s=int(globals()["byte_send_server"])
            time_s=float(globals()["time_send_server"])
        if byte_s==0:
            byte_s=65535
            time_s=0
        len_data = -1
        if reset_send_data_user!=0:
            time=time_count+(reset_send_data_user*60)
        else:
            time=-1
        try:
            string = " "
            while string:
                if len_data<max_data_user:
                    string = source.recv(byte_s)
                    if string:
                        if max_data_user>0 and is_user_send==0:
                            len_data+=len(string)
                        destination.sendall(string)
                    else:
                        source.shutdown(socket.SHUT_RD)
                        destination.shutdown(socket.SHUT_WR)
                    sleep(time_s)
                else:
                    print("[FORWARD_INFO] Out of data on {} min: Port {} from {} ({} byte)".format(reset_send_data_user,port,ip,max_data_user))
                    # if type_block_send_data!=0:
                    block.append(ip)
                    block_ip(ip,source)
                    break
                if time==-1:
                    continue
                elif time_count>time and max_data_user>0:
                    time=time_count+(reset_send_data_user*60)
                    len_data=0
        except TimeoutError:
            print("[INFO_ERR]>> Timeout: Port {} from {}".format(str(port),str(ip)))
        except ConnectionAbortedError:
            print("[INFO_ERR]>> Aborted connection: Port {} from {}".format(str(port),str(ip)))
        except ConnectionResetError:
            print("[INFO_ERR]>> Close connection: Port {} from {}".format(str(port),str(ip)))
        except ConnectionRefusedError:
            print("[INFO_ERR]>> Connection refused: Port {} from {}".format(str(port),str(ip)))
        except:
            pass
        if is_a==1:
            global count_conn
            count_conn-=1
            for i in [s for s in all_conn if "conn_{}:{}".format(ip,b) in s]:
                try:
                    all_conn.remove(i)
                except:
                    pass
            # all_conn.remove("conn_"+str(ip)+":"+str(b)) <- old not worked, replaced
            del globals()["conn_"+str(ip)+":"+str(b)]
        try:
            source.shutdown(socket.SHUT_RD)
            destination.shutdown(socket.SHUT_WR)
        except:
            return

    def close_conn():
        global all_conn, soc
        try:
            soc.close()
        except:
            pass
        for i in all_conn:
            try:
                print(i)
            except:
                pass
        return

    def block_ip(con_ip,a):
        global ddos, force_block, list_ban_ip, time_count, all_conn
        force_block[con_ip]=0
        if block_time!=0:
            print("[INFO_BLOCK] Block {} for {} minutes".format(con_ip,block_time))
            Thread(target=block_with_time, args=(con_ip,time_count+(block_time*60),0)).start()
        print("[INFO_BLOCK] Close all connection from {}".format(con_ip))
        try:
            a.close()
        except:
            pass
        for i in [d for d in all_conn if "conn_{}:".format(con_ip) in d]:
            try:
                all_conn.remove(i)
            except:
                pass
            try:
                globals()[i].close()
            except:
                pass
        return

    def open_port(port):
        global ddos, block, force_block, list_ban_ip, max_conn, count_conn, all_conn, soc, count_ip
        current_conn=[]
        all_conn=[]
        count=0
        count_conn=0
        soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            soc.bind((str(host_fake), int(port)))
            soc.listen(9)
            Thread(target=time_run, args=()).start()
            print("[!!] >> Started! Anti-DDoS protection")
            while 1:
                try:
                    a,b = soc.accept()
                    if (b[0] in block):
                        a.close()
                        if (force_firewall_count>0):
                            try:
                                force_block[b[0]]+=1
                            except:
                                force_block[b[0]]=1
                            if (force_block[b[0]]>force_firewall_count):
                                print("!! Detected {0} try request {1} times! Blocking...".format(str(b[0]),str(force_block[count_ip])))
                                Thread(target=block_ip, args=(b[0],a)).start()
                                force_block[b[0]]=0
                                continue
                            print("Blocked connection from {0} ({1})".format(b[0],force_block[b[0]]))
                        else:
                            print("Blocking connection from {0}".format(b[0]))
                    else:
                        if (count_conn<=max_conn) or (b[0] in current_conn):
                            try:
                                ddos[b[0]]+=1
                            except KeyError:
                                ddos[b[0]]=1
                            try:
                                if (ddos[b[0]]>block_on_count):
                                    print("!! Detected DDOS from {}! Blocking...".format(b[0]))
                                    block.append(b[0])
                                    Thread(target=block_ip, args=(b[0],a)).start()
                                    continue
                            except:
                                ddos[b[0]]=1
                            if b[0] not in current_conn:
                                count_conn+=1
                                is_a=1
                            else:
                                is_a=0
                            current_conn.append(b[0])
                            all_conn.append("conn_"+str(b[0])+":"+str(b[1]))
                            globals()["conn_"+str(b[0])+":"+str(b[1])]=a
                            count+=1
                            print(f"{count}. Port {port} -> {port_real} | Accept: {b[0]} ({ddos[b[0]]})")
                            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            server_socket.settimeout(5)
                            server_socket.connect((str(host_real), int(port_real)))
                            server_socket.settimeout(timeout_conn)
                            a.settimeout(timeout_conn)
                            Thread(target=forward, args=(b[0],port,a,server_socket,1,is_a,b[1])).start()
                            Thread(target=forward, args=(b[0],port,server_socket,a,0,0)).start()
                        else:
                            print("Full connection {}".format(b[0]))
                            a.close()
                    sleep(float(time_connect))
                except OSError as e:
                    if '[closed]' not in str(soc):
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
        
    def about():
        while 1:
            clear()
            a=str(input("[ABOUT_INFO] About this program\n\n1. Github\n2. Readme\n0. Back\n\n >> Your choose: "))
            if (a=="1"):
                system("start \"\" \"https://github.com/iFanpSGTS\"")
            elif (a=="2"):
                clear()
                print("This program is fully rewrite by iFanpSGTS, and also big credit \
for https://github.com/KhanhNguyen9872/Anti-DDOS_Win.\nThis program code is basically from his github \
but rewrited by iFanpSGTS")
                input()
                break
            elif (a=="0"):
                break
            
    def run_program():
        while run_flag==True:
            clear()
            print("[INFO_START] Program is running! Choose option\n1. Anti-DDOS [Fake Port {0}]\n2. About\n0. Exit\n\n".format(str(port_fake)))
            ask=str(input(">> Your choose: "))
            if (ask == "1"):
                start(port_fake)
            elif (ask == "2"):
                about()
            elif (ask == "0"):
                kill_process()
            continue
        
    def start(port):
        clear()
        global ddos
        print("\n[RUNNING ON] config fake: http://{0}:{1} -> http://{2}:{3}".format(str(host_fake),str(port_fake),str(host_real),str(port_real)))
        print(f"[/] >> Starting Anti-DDOS...")
        Thread(target=open_port, args=(port,)).start()
        sleep(2)
        while 1:
            try:
                print("[/] No DDOS in {} seconds, reset count...".format(str(reset_on_time)))
                ddos={}
                sleep(float(reset_on_time))
            except KeyboardInterrupt:
                print("[INFO_CON_STOP] Stopping all connection.... on start")
                kill_process()
                close_conn()
                    
    from os import kill, getpid, name, system, remove
    clear()
    try:
        from config import *
    except:
        print("[CONFIG_ERR]>> config.py not found or syntax error!")
        input()
        sys.exit()
    from urllib.parse import unquote
    from subprocess import Popen, PIPE
    from time import sleep
    from threading import Thread
    from random import choice
    import socket, signal
    try:
        from subprocess import DEVNULL
    except ImportError:
        from os import devnull
        DEVNULL = open(devnull, 'wb')
    global pid, ddos, block, force_block, list_ban_ip, blockk
    global run_flag
    pid = getpid()
    ddos={}
    block=[]
    blockk=[]
    run_flag=True
    list_ban_ip=str(ban_ip).replace("/32","")
    force_block={}
    try:
        if (int(len([str(x) for x in host_fake.split(".") if x and x!="\n"])+len([str(x) for x in host_real.split(".") if x and x!="\n"])) != 8):
            print("[INFO_ERR_CONF] ip fake or real may be not correct!")
            _=int("valueError")
        if int(max_speed_user)<0:
            print("[INFO_ERR_CONF] max speed user should not be less than 0")
            _=int("valueError")
        if int(max_speed_server)<0:
            print("[INFO_ERR_CONF] max speed server should not be less than 0")
            _=int("valueError")
        if int(timeout_conn)<1:
            print("[INFO_ERR_CONF] timeout conn should not be less than 1")
            _=int("valueError")
        if int(reset_send_data_user)<0:
            print("[INFO_ERR_CONF] reset send data user should not be less than 0")
            _=int("valueError")
        if int(max_conn)<1:
            print("[INFO_ERR_CONF] max conn should not be less than 1")
            _=int("valueError")
        if int(max_data_user)<0:
            print("[INFO_ERR_CONF] max data should not be less than 0")
            _=int("valueError")
        if int(port_real)<1 and int(port_real)>65535:
            print("[INFO_ERR_CONF] Port real must in range 1-65535")
            _=int("valueError")
        if int(port_fake)<1 and int(port_fake)>65535:
            print("[INFO_ERR_CONF] Port fake must in range 1-65535")
            _=int("valueError")
        if int(port_fake)==int(port_real):
            print("[INFO_ERR_CONF] Port fake and real must not the same!")
            _=int("valueError")
        if float(time_connect)<0:
            print("[INFO_ERR_CONF] time connect should not be less than 0")
            _=int("valueError")
        if int(block_on_count)<1:
            print("[INFO_ERR_CONF] Block on count should not be less than 1")
            _=int("valueError")
        if int(reset_on_time)<1:
            print("[INFO_ERR_CONF] Reset on time should not be less than 1")
            _=int("valueError")
        if int(is_get_sock)==1 or int(is_get_sock)==0:
            pass
        else:
            print("[INFO_ERR_CONF] is get sock must be 0 or 1")
            _=int("valueError")
        _=ban_sock
        _=headers
    except:
        print("\n[CONFIG_ERR]>> Config file is error!")
        input("[ERROR_INFO] press to exit...!")
        kill_process()
    global byte_send_user, byte_send_server, time_send_user, time_send_server
    byte_send_user = int((max_speed_user * 1024 * 1024)/70)
    time_send_user = 1/1000
    byte_send_server = int((max_speed_user * 1024 * 1024)/70)
    time_send_server = 1/1000
    if (int(is_get_sock)==1):
        try:
            with open("proxy.txt","r") as f:
                while 1:
                    clear()
                    ask=str(input("[PROXYFILE_INFO] Found: proxy.txt\n[PROXYFILE_INFO] Note: Y for load proxy, N for download new sock proxy\n[PROXYFILE_INFO] >> Do you want to load proxy from this file? [Y/N]: "))
                    if (ask == "Y") or (ask == "y"):
                        exec("global blockk; {}".format(f.read()))
                        print("\n[PROXY] Total IP Sock: {} IP".format(str(len(blockk))))
                        print("[PROXY] Real IP Sock: {} IP".format(str(len(list(set(blockk))))))
                        input("[##] Press Enter to Start!")
                        break
                    elif (ask == "N") or (ask == "n"):
                        print()
                        _=int("valueError")
                        break
        except:
            import urllib.request, ssl; from random import choice
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            print("[/] Downloading Sock Proxy....")
            total_ip = 0
            for sock in ban_sock:
                count_ip = 0
                print("GET: {}".format(sock), end=" ")
                sys.stdout.flush()
                req = urllib.request.Request(sock, headers={'User-Agent': choice(headers)})
                try:
                    # Create a custom HTTPSHandler with disabled certificate verification
                    https_handler = urllib.request.HTTPSHandler(context=ssl_context)
                    opener = urllib.request.build_opener(https_handler)
                    response = opener.open(req, timeout=15)
                    if response.getcode() == 200:
                        ips = response.read().decode().replace('\r', '').split('\n')
                        for ip in ips:
                            try:
                                temp = str(ip.split(':')[0])
                                int("".join(temp.split(".")))
                                if ip and len(temp.split(".")) == 4:
                                    blockk.append(temp)
                                    count_ip += 1
                            except:
                                continue
                        print("[PROXY_GET_STATUS] (OK - {} IP)".format(str(count_ip)))
                        total_ip += count_ip
                    else:
                        print("[PROXY_GET_STATUS] (DIED)")
                except urllib.error.URLError as e:
                    print("[PROXY_GET_STATUS] (DIED - {})".format(str(e.reason)))
            del temp
            blockk=list(set(blockk))
            print("\n[PROXY_FOUND] Total IP Sock: {} IP".format(str(total_ip)))
            print("[PROXY_FOUND] Real IP Sock: {} IP".format(str(len(blockk))))
            asks=str(input("\n[PROXY_FOUND] NOTE: Y for save to file, N for skip save\n>> Do you want to save Real IP? [Y/N]: "))
            while 1:
                if (asks == "Y") or (asks == "y"):
                    with open("proxy.txt","w") as f:
                        f.write("blockk={}".format(str(blockk)))
                    break
                elif (asks == "N") or (asks == "n"):
                    remove("proxy.txt")
                    break
        print("[PROXY_FOUND] Processing IP....")
        for _ in blockk:
            block.append(str(_))
        del blockk
    block=list(set(block))
    clear()
    print("[INFO_WARN] Warning: This tool only Anti-DDOS TCP Port, please block all UDP Port, because your server may be UDPFlood!\n")
    input("[##] Press Enter to continue! ")
    try:
        run_program()
    except KeyboardInterrupt:
        print("[##] Stopping all connection....")
        close_conn()
        kill_process()