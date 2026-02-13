#!/usr/bin/env bash
# ==========================================================
# Virtual Household — RECEIVER (server — listens for uplink)
# ==========================================================
# Each TCP flow needs its own port for independent connections.
# Uses socat -u (unidirectional) as a TCP sink: reads from the
# TCP socket and discards data.  The -u flag is critical —
# without it, socat reads EOF from /dev/null and closes the
# connection immediately.
# Sender-side TCPINFO provides all needed TCP stats.
# ==========================================================

# --- TCP sinks (socat -u) ---
# Start a unidirectional socat sink for each TCP port:
socat -u TCP-LISTEN:5001,fork,reuseaddr OPEN:/dev/null &
socat -u TCP-LISTEN:5101,fork,reuseaddr OPEN:/dev/null &

# Or if socat is not available, use this Python one-liner:
# python3 -c "import socket,threading;ports=[5001,5101]
# def d(c):
#  try:
#   while c.recv(65536): pass
#  except: pass
#  finally: c.close()
# def s(p):
#  k=socket.socket();k.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
#  k.bind(('',p));k.listen(64)
#  while True:
#   c,_=k.accept();threading.Thread(target=d,args=(c,),daemon=True).start()
# for p in ports: threading.Thread(target=s,args=(p,),daemon=True).start()
# import time
# try: 
#  while True: time.sleep(3600)
# except KeyboardInterrupt: pass" &

echo "Receiver sinks started. Press Ctrl+C to stop."
wait
