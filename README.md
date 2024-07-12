# Docs
- Config.py
  ## limit speed / 1 second (user to server) (megabyte/second)
  max_speed_user = 4   # 4mb/s   # 0 for unlimited
  
  ## limit speed / 1 second (server to user) (megabyte/second)
  max_speed_server = 4   # 4mb/s   # 0 for unlimited
  
  ## max ip can connect in one time
  ## user can connect again at next time without +conn!
  max_conn = 30  # 30 connection
  
  ## max send or receive data on each connection from user to server (byte)
  max_data_user = 42428800  # 50mb        # use 0 for disable
  
  ## reset user send data length on [minutes], 0 for disable
  reset_send_data_user = 1  # 1 minutes
  
  ## block time on [minutes] if spam or send data large than max_data_user, 0 for disable
  ## this will unblock after your input minutes
  block_time = 20  # 30 minutes
  
  ## timeout a connection on [minutes] when user or server not send any data
  ## user can connect again when timeout
  timeout_conn = 180  # 180 seconds
  
  ## ip host fake
  host_fake="127.0.0.1"
  
  ## ip host real
  host_real="192.168.0.102"
  
  ## Fake port for open port firewall
  port_fake=8001
  
  ## Real port for your program listen port
  port_real=8000
  
  ## only accept 1 client in [seconds]
  time_connect=0  # 0 second (recommend is 0)
  
  ## Block ip when this ip requested to fake port large than count
  ## WARNING! Changing to a very low value may block you and your users from the Windows VPS
  block_on_count=20  # 15 times
  
  ## Time reset count [second]
  reset_on_time=60  # 60 seconds
  
  ## Force add ip to windows firewall if block ip try request large than count
  force_firewall_count=0 # (recommend is 0)
  
  ## Default IP Blocked
  ban_ip=""
  
  ## 1 for Enable get all IP Sock for block, 0 for Disable
  is_get_sock=1

# Updates
  - Basically https://github.com/KhanhNguyen9872/Anti-DDOS_Win code but rewrited so now it can used on Linux OS.
  - Still cannot block botnet, but now after using IPTables and new logic algorithm it can block 2TB+ Booter.

# Usage
  - ```py
    python ddos_protection.py
    ```

# Credit
  - https://github.com/KhanhNguyen9872
  - https://github.com/KhanhNguyen9872/Anti-DDOS_Win
  
