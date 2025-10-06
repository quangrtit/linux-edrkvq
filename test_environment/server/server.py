import socket, ssl, threading, argparse, json
import time
CLIENTS = set()
ioc_update_file_hashes_list = ["e11ecafd9e8afcec666fdfb89deddbba92f091c29062dc3bee2b053ee5881c98"] # main_test_block_exe
ioc_update_ips_list = ["222.255.113.97"] # https://daotao.ptit.edu.vn/

ioc_delete_file_hashes_list = ["e11ecafd9e8afcec666fdfb89deddbba92f091c29062dc3bee2b053ee5881c98"]
ioc_delete_ips_list = ["222.255.113.97"]

white_list_pid = []
def build_ioc(type, file_hashes, ips, source="admin"):
    ts = int(time.time())
    file_hash_objs = [
        {
            "value": h,
            "first_seen": ts,
            "last_seen": ts,
            "source": source
        } for h in file_hashes
    ]
    ip_objs = [
        {
            "value": ip,
            "first_seen": ts,
            "last_seen": ts,
            "source": source
        } for ip in ips
    ]
    msg = {
        "type": type,
        "timestamp": ts,
        "data": {
            "file_hashes": file_hash_objs,
            "ips": ip_objs
        }
    }
    return json.dumps(msg)
def handle_client(conn, addr):
    print(f"[+] Connection from {addr}")
    CLIENTS.add(conn)
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            msg = data.decode().strip()
            print(f"[Client {addr}] {msg}")
    except Exception as e:
        print(f"[-] Error with {addr}: {e}")
    finally:
        CLIENTS.discard(conn)
        conn.close()
        print(f"[-] Disconnected {addr}")

def broadcast_command(command: str):
    payload = json.dumps({"type": command}) + "\n"
    if command == "ioc_update": 
        payload = build_ioc(command, ioc_update_file_hashes_list, ioc_update_ips_list)
    elif command == "ioc_delete":
        payload = build_ioc(command, ioc_delete_file_hashes_list, ioc_delete_ips_list)
    dead_clients = []
    for c in CLIENTS:
        try:
            c.sendall(payload.encode())
        except Exception:
            dead_clients.append(c)
    for c in dead_clients:
        CLIENTS.discard(c)
        try:
            c.close()
        except:
            pass

def run_server(port, certfile, keyfile, cafile, enable_mtls):
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    if enable_mtls:
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cafile)

    bindsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    bindsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    bindsock.bind(("0.0.0.0", port))
    bindsock.listen(5)
    print(f"[*] TLS Server listening on 0.0.0.0:{port}")

    def admin_loop():
        while True:
            cmd = input("Enter command (any text | quit): ").strip()
            if cmd.lower() == "quit":
                print("Shutting down server...")
                bindsock.close()
                for c in list(CLIENTS):
                    c.close()
                break
            elif cmd:
                print(f"[Admin] Broadcasting command: {cmd}")
                broadcast_command(cmd)

    threading.Thread(target=admin_loop, daemon=True).start()

    while True:
        try:
            newsock, fromaddr = bindsock.accept()
            conn = context.wrap_socket(newsock, server_side=True)
            threading.Thread(target=handle_client, args=(conn, fromaddr), daemon=True).start()
        except Exception as e:
            print(f"Server error: {e}")
            break

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='TLS socket server.')
    parser.add_argument('-p', '--port', type=int, required=True)
    parser.add_argument('-c', '--certfile', type=str, required=True)
    parser.add_argument('-k', '--keyfile', type=str, required=True)
    parser.add_argument('-a', '--cafile', type=str, help='CA cert for client verification')
    parser.add_argument('-m', '--mtls', action='store_true', help='Enable mutual TLS')

    args = parser.parse_args()
    run_server(args.port, args.certfile, args.keyfile, args.cafile, args.mtls)
"""
{
  "type": "ioc_update",
  "timestamp": 1727359200,
  "data": {
    "file_hashes": [
      {
        "value": "ccf29345b53dd399ee1a1561e99871b2d29219682392e601002099df77c18709",
        "first_seen": 1727359000,
        "last_seen": 1727359000,
        "source": "admin"
      }
    ], 
    "ips": [
      {
        "value": "192.140.87.197",
        "first_seen": 1727359000,
        "last_seen": 1727359000,
        "source": "admin"
      }
    ]
  }
}
"""
