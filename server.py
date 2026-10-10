import socket
import threading
import json
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import traceback
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA3_512, HMAC as CryptoHMAC 
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
import base64

# client object to store each client info
class Client:

    def __init__(self, sock, username, channel):
        self.sock = sock
        self.username = username
        self.channel = channel
        self.authenticated = False
        self.alive = True

    # send helper
    def send(self, data):
        try:
            self.sock.sendall((json.dumps(data) + "\n").encode())
        except:
            self.alive = False


    # gracful disconnect
    def disconnect(self):

        if not self.alive:
            return

        self.alive = False

        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except:
            pass

        try:
            self.sock.close()
        except:
            pass


class Server:

    CHANNELS = ["IF100", "MATH101", "SPS101"]

    def __init__(self, root):

        self.root = root
        self.root.title("Server")
        self.root.geometry("1400x800")

        self.server_socket = None
        self.running = False

        self.clients = []
        self.client_lock = threading.Lock()

        # channel crypto data, with inital none values
        self.channel_data = {
            "IF100": {
                "aes_key": None,
                "iv": None,
                "hmac_key": None
            },
            "MATH101": {
                "aes_key": None,
                "iv": None,
                "hmac_key": None
            },
            "SPS101": {
                "aes_key": None,
                "iv": None,
                "hmac_key": None
            }
        }

        # load RSA keys
        with open("server_enc_dec_pub_prv.pem", "rb") as f:
            self.rsa_key = RSA.import_key(f.read())
        with open("server_sign_verify_prv.pem", "rb") as f:
            self.sign_key = RSA.import_key(f.read())

        self.setup_ui()

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)


    def setup_ui(self):

  
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_columnconfigure(1, weight=3)
        self.root.grid_rowconfigure(0, weight=1)

        self.left_frame = tk.Frame(self.root, padx=10, pady=10)
        self.left_frame.grid(row=0, column=0, sticky="ns")

        self.right_frame = tk.Frame(self.root, padx=10, pady=10)
        self.right_frame.grid(row=0, column=1, sticky="nsew")

        self.create_server_controls()
        self.create_channel_controls()
        self.create_online_users()
        self.create_logs()

    # server control
    def create_server_controls(self):

        frame = tk.LabelFrame(self.left_frame, text="Server Controls")
        frame.pack(fill="x", pady=5)

        tk.Label(frame, text="IP").pack(anchor="w")

        self.ip_entry = tk.Entry(frame)
        self.ip_entry.insert(0, "127.0.0.1")
        self.ip_entry.pack(fill="x", pady=2)

        tk.Label(frame, text="Port").pack(anchor="w")

        self.port_entry = tk.Entry(frame)
        self.port_entry.insert(0, "5050")
        self.port_entry.pack(fill="x", pady=2)

        self.server_btn = tk.Button(
            frame,
            text="Start Server",
            command=self.toggle_server
        )
        self.server_btn.pack(fill="x", pady=5)

    # channel key controls
    def create_channel_controls(self):

        self.channel_frames = {}

        for channel in self.CHANNELS:

            frame = tk.LabelFrame(
                self.left_frame,
                text=f"{channel} Channel"
            )

            frame.pack(fill="x", pady=5)

            tk.Label(frame, text="Master Secret").pack(anchor="w")

            secret_entry = tk.Entry(frame)
            secret_entry.pack(fill="x", pady=2)

            gen_btn = tk.Button(
                frame,
                text="Generate Keys",
                command=lambda c=channel, e=secret_entry:
                self.generate_channel_keys(c, e.get())
            )

            gen_btn.pack(fill="x", pady=2)

            self.channel_frames[channel] = {
                "entry": secret_entry,
                "button": gen_btn
            }
        
        self.broadcast_btn = tk.Button(
            self.left_frame,
            text="Broadcast Keys",
            command=self.broadcast_all_keys
        )

        self.broadcast_btn.pack(fill="x", pady=10)

    # online users board
    def create_online_users(self):

        frame = tk.LabelFrame(self.left_frame, text="Online Users")
        frame.pack(fill="both", expand=True, pady=5)

        self.online_box = scrolledtext.ScrolledText(
            frame,
            height=10,
            state=tk.DISABLED
        )

        self.online_box.pack(fill="both", expand=True)

        self.online_box.config(state=tk.NORMAL)
        self.online_box.delete("1.0", tk.END)
        self.online_box.insert(
            tk.END,
            f"{'USERNAME':<31}CHANNEL\n"
        )
        self.online_box.insert(
            tk.END,
            "-" * 38 + "\n"
        )
        self.online_box.config(state=tk.DISABLED)

    # log sections
    def create_logs(self):

        self.right_frame.grid_rowconfigure(0, weight=1)
        self.right_frame.grid_rowconfigure(1, weight=1)
        self.right_frame.grid_columnconfigure(0, weight=1)
        self.right_frame.grid_columnconfigure(1, weight=1)

        # server log
        server_frame = tk.LabelFrame(self.right_frame, text="Server Logs")
        server_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        self.log_box = scrolledtext.ScrolledText(
            server_frame,
            state=tk.DISABLED
        )

        self.log_box.pack(fill="both", expand=True)

        # crypto log
        crypto_frame = tk.LabelFrame(self.right_frame, text="Crypto Logs")
        crypto_frame.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)
        self.crypto_box = scrolledtext.ScrolledText(
            crypto_frame,
            state=tk.DISABLED
        )

        self.crypto_box.pack(fill="both", expand=True)

        # channel logs
        self.channel_boxes = {}

        bottom = tk.Frame(self.right_frame)
        bottom.grid(row=1, column=0, columnspan=2, sticky="nsew")
        bottom.grid_columnconfigure(0, weight=1)
        bottom.grid_columnconfigure(1, weight=1)
        bottom.grid_columnconfigure(2, weight=1)

        for i, channel in enumerate(self.CHANNELS):

            frame = tk.LabelFrame(bottom, text=channel)
            frame.grid(row=0, column=i, sticky="nsew", padx=5, pady=5)
            txt = scrolledtext.ScrolledText(
                frame,
                state=tk.DISABLED
            )
            txt.pack(fill="both", expand=True)
            self.channel_boxes[channel] = txt

    # server start/stop toggle switch
    def toggle_server(self):

        if not self.running:
            self.start_server()
        else:
            self.stop_server()

    # start the server
    def start_server(self):

        # log RSA keys
        self.log_crypto(f"Server RSA Private Key: {self.rsa_key.export_key().decode('utf-8')}")
        self.log_crypto(f"Server Signature RSA Private Key: {self.sign_key.export_key().decode('utf-8')}")

        ip = self.ip_entry.get().strip()

        try:
            port = int(self.port_entry.get().strip())
        except:
            messagebox.showerror("Error", "Invalid port")
            return

        try:

            self.server_socket = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM
            )

            self.server_socket.bind((ip, port))
            self.server_socket.listen()

            self.running = True

            threading.Thread(
                target=self.accept_clients,
                daemon=True
            ).start()

            self.server_btn.config(text="Stop Server")

            self.log_server(f"Server started on {ip}:{port}")

        except Exception as e:
            messagebox.showerror(
                "Server Error",
                str(e)
            )

    # stop the server, disconnect each client
    def stop_server(self):

        self.running = False

        with self.client_lock:

            for client in self.clients[:]:
                client.disconnect()

            self.clients.clear()

        try:
            self.server_socket.close()
        except:
            pass

        self.server_btn.config(text="Start Server")

        self.log_server("Server stopped")

        self.update_online_users()

    # client accepter
    def accept_clients(self):

        while self.running:

            try:

                sock, addr = self.server_socket.accept()

                self.log_server(f"Incoming connection: {addr}")

                # half completed object, used for disconnecting connected but not authenticated users
                client_obj = Client(
                    sock,
                    None,
                    None
                )

                with self.client_lock:
                    self.clients.append(client_obj)

                # client handler thread
                threading.Thread(
                    target=self.handle_client,
                    args=(client_obj,),
                    daemon=True
                ).start()

            except:
                break

    # main client thread
    def handle_client(self, client_obj):

        sock = client_obj.sock
        try:
            
            # every client start unauthed
            authenticated = False

            # if not authed, command is either enroll or login
            while not authenticated:

                msg = self.recv_packet(sock)

                if msg is None:
                    return

                # get command
                command = msg.get("command")


                if command == "ENROLL": # if enroll, call proper function
                    self.handle_enroll(client_obj, msg)


                elif command == "LOGIN":# if login, call proper function

                    client_obj = self.handle_login(client_obj, msg)

                    if client_obj.username:
                        authenticated = True

                else: # block unknown commands, and unauthenticated access

                    self.send_packet(sock, {
                        "command": "ERROR",
                        "message": "Authenticate first"
                    })

                    self.log_server(f"Not enrolled user {msg.get("username")} is rejected")

            # messaging logic after authentication
            while True:

                msg = self.recv_packet(sock)

                if msg is None:
                    break

                command = msg.get("command")

                # receiving a message froma client
                if command == "MESSAGE":

                    self.broadcast_message(
                        client_obj.channel,
                        msg
                    )

                    self.log_channel(client_obj.channel,f"{client_obj.username} sent message, relaying")

        except ConnectionResetError:
            pass
        except Exception:
            traceback.print_exc()

        finally: # finally, disconnect the client gracefully

            if client_obj:

                self.log_server(
                    f"{client_obj.username} disconnected"
                )

                with self.client_lock:

                    if client_obj in self.clients:
                        self.clients.remove(client_obj)

                self.update_online_users()

            try:
                sock.close()
            except:
                pass

    # handle enroll
    def handle_enroll(self, client_obj, msg):

        sock = client_obj.sock

        # retreive data and decrypt with RSA priv key
        data = base64.b64decode(msg.get("data"))
        data = PKCS1_OAEP.new(self.rsa_key).decrypt(data)

        # split the concentrated string and assing to correct fields 
        parts = data.split(b"|", 3)
        username = parts[0].decode("utf-8")
        pw_hash = parts[1].decode("utf-8")
        rev_pw_hash = parts[2].decode("utf-8")
        channel = parts[3].decode("utf-8")

        self.log_server(f"Received enrollment request, username: {username}, channel: {channel}")

        # Load users
        try:
            with open("users.json", "r") as file:
                users = json.load(file)
        except FileNotFoundError:
            users = {}

        # Username exists
        if username in users:
            # prepare a response
            response = {
                "command": "ENROLL_RESULT",
                "status": "fail",
                "reason": "Another user with same username exists"
            }
            self.log_server(f"User {username} is rejected: Another user with same username exists")

        else: # else, unique user

            # save the user
            users[username] = {
                "pw_hash": pw_hash,
                "rev_pw_hash": rev_pw_hash,
                "channel": channel
            }
            with open("users.json", "w") as file:
                json.dump(users, file, indent=4)

            # prepare a response
            response = {
                "command": "ENROLL_RESULT",
                "status": "success"
            }

        # sign and send the appropiate response
        payload_bytes = json.dumps(
            response,
            sort_keys=True # sort for consistency
        ).encode("utf-8")

        rsp_hash = SHA3_512.new(payload_bytes)

        signature = PKCS1_PSS.new(
            self.sign_key
        ).sign(rsp_hash)

        # final packet including response and signature
        final_packet = {
            "payload": response,
            "signature": base64.b64encode(signature).decode("utf-8")
        }

        self.log_crypto(f"{username} enroll request response signature: {signature.hex()}")

        self.send_packet(sock, final_packet)

        self.log_server(f"User {username} is enrolled to {channel}")

    # handle login
    def handle_login(self, client_obj, msg):

        sock = client_obj.sock

        username = msg.get("username")

        self.log_server(
            f"Login request: {username}"
        )

        # load users
        try:
            with open("users.json", "r") as file:
                users = json.load(file)
        except FileNotFoundError:
            users = {}

        # check for username
        if username not in users: # username not found

            self.send_packet(sock, {"command": "LOGIN_FAILED","reason":"Enrollment not found"})
            self.log_server(f"User {username} is rejected: Enrollment not found")
            return client_obj
        
        elif any(client.username == username for client in self.clients): # username already connected
            self.send_packet(sock, {"command": "LOGIN_FAILED", "reason":"User already logged in"})
            self.log_server(f"User {username} is rejected: User already logged in")
            return client_obj

        # retreive aes values for encrypting response/channel keys, used later (after successful challenge-response)
        pw_hash = bytes.fromhex(users[username]["pw_hash"])
        rev_pw_hash = bytes.fromhex(users[username]["rev_pw_hash"])
        aes_key = rev_pw_hash[0:32]
        iv = rev_pw_hash[32:48]
        channel = users[username]["channel"]

        self.log_crypto(f"User {username} Login AES Key: {aes_key.hex()}")
        self.log_crypto(f"User {username} Login AES IV: {iv.hex()}")

        # get 128 bit random challenge
        challenge = get_random_bytes(16)

        self.log_crypto(f"User {username} Challenge: {challenge.hex()}")

        # send the challenge
        self.send_packet(sock, {
            "command": "LOGIN_CHALLENGE",
            "challenge": base64.b64encode(challenge).decode("utf-8")
        })

        # wait for hmac response
        response = self.recv_packet(sock)

        # safeguards
        if response is None:
            return None
        if response.get("command") != "LOGIN_RESPONSE":
            result = {
                "command": "LOGIN_FAILED","reason":"Incorrect Command"
            }
            self.log_server(f"User {username} rejected: Incorrect Command")
            # encrypt and sign negative ack
            plaintext = json.dumps(result).encode()
            ciphertext = AES.new(aes_key, AES.MODE_CBC, iv).encrypt(pad(plaintext,AES.block_size))
            ciphertext_hash = SHA3_512.new(ciphertext)
            signature = PKCS1_PSS.new(self.sign_key).sign(ciphertext_hash)
            msg = {
                "payload": base64.b64encode(ciphertext).decode(),
                "signature":base64.b64encode(signature).decode()
            }
            self.send_packet(sock, msg)
            return client_obj

        # prepare hmac for verification
        hmac_hex = response.get("response")

        hmac_key = pw_hash[0:32]
        self.log_crypto(f"User {username} Challenge HMAC Key: {hmac_key.hex()}")

        try:
            
            # compare hmacs
            verifier = CryptoHMAC.new(
                hmac_key,
                digestmod=SHA3_512
            )
            verifier.update(challenge)
            verifier.hexverify(hmac_hex)

            self.log_server(
                f"HMAC verified, {username} authenticated"
            )

        except ValueError: # if invalid, send failed response

            self.log_server(f"{username} rejected: failed HMAC auth")
            result = {"command": "LOGIN_FAILED", "reason": "Challenge Failed/Incorrect Password"}
            plaintext = json.dumps(result).encode()

            # encrypt and sign negative ack
            ciphertext = AES.new(aes_key, AES.MODE_CBC, iv).encrypt(pad(plaintext,AES.block_size))
            ciphertext_hash = SHA3_512.new(ciphertext)
            signature = PKCS1_PSS.new(self.sign_key).sign(ciphertext_hash)
            msg = {
                "payload": base64.b64encode(ciphertext).decode(),
                "signature":base64.b64encode(signature).decode()
            }
            self.send_packet(sock, msg)

            return client_obj

        # fill the rest of client obj fields
        client_obj.username = username
        client_obj.channel = channel
        client_obj.authenticated = True

        self.update_online_users()

        # send pos ack
        if self.channel_data[channel]["aes_key"] is None:
            result = {
                "command": "LOGIN_SUCCESS",
                "channel": channel,
                "channel_data": self.channel_data[channel]
            }
        else:
            result = {
                "command": "LOGIN_SUCCESS",
                "channel": channel,
                "channel_data": {
                    "aes_key": self.channel_data[channel]["aes_key"].hex(),
                    "iv": self.channel_data[channel]["iv"].hex(),
                    "hmac_key": self.channel_data[channel]["hmac_key"].hex()
                } 
            }

        plaintext = json.dumps(result).encode()

        # encrytp and sign
        ciphertext = AES.new(aes_key, AES.MODE_CBC, iv).encrypt(pad(plaintext,AES.block_size))
        ciphertext_hash = SHA3_512.new(ciphertext)
        signature = PKCS1_PSS.new(self.sign_key).sign(ciphertext_hash)

        msg = {
            "payload": base64.b64encode(ciphertext).decode(),
            "signature":base64.b64encode(signature).decode()
        }

        self.send_packet(sock, msg)

        self.log_server(f"{username} successfully logged in, sending {channel} keys")

        return client_obj


    # broadcast a message to all clients
    def broadcast_message(self, channel, msg):

        with self.client_lock:

            for client in self.clients:

                if client.channel == channel and client.alive:

                    client.send(msg)

    # generate channel keys
    def generate_channel_keys(self, channel, secret):

        if not secret:
            messagebox.showerror(
                "Error",
                "Master secret cannot be empty"
            )
            return

        reverse_secret = secret[::-1]
        # hash
        secret_hash = SHA3_512.new(data=secret.encode()).digest()
        rev_secret_hash = SHA3_512.new(data=reverse_secret.encode()).digest()

        # derive keys
        aes_key = secret_hash[0:32]
        iv = secret_hash[32:48]
        hmac_key = rev_secret_hash[0:32]

        # save the keys
        self.channel_data[channel] = {
            "aes_key": aes_key,
            "iv": iv,
            "hmac_key": hmac_key
        }

        self.log_crypto(f"{channel} key generated")

        self.log_crypto(f"{channel} AES Key: {aes_key.hex()}")
        self.log_crypto(f"{channel} AES IV: {iv.hex()}")
        self.log_crypto(f"{channel} HMAC Key: {hmac_key.hex()}")

        self.channel_frames[channel]["button"].config(state=tk.DISABLED)

    # broadcast current keys to all clients, with respect to their subscribed channel
    def broadcast_all_keys(self):

        self.log_server("Broadcasting current channel keys")

        try:
            with open("users.json", "r") as file:
                users = json.load(file)
        except FileNotFoundError:
            users = {}

        with self.client_lock:
            for client in self.clients:
                channel = client.channel

                # retrieve channel kets
                # if not none, safe to use .hex()
                if self.channel_data[channel]["aes_key"] is not None:
                    channel_data = {
                        "aes_key": self.channel_data[channel]["aes_key"].hex(),
                        "iv": self.channel_data[channel]["iv"].hex(),
                        "hmac_key": self.channel_data[channel]["hmac_key"].hex()
                    } 
                else: # else, keys are None, nothing is changed
                    continue

                # retrieve AES key + iv form reverse pw hash
                rev_pw_hash = bytes.fromhex(users[client.username]["rev_pw_hash"])
                aes_key = rev_pw_hash[0:32]
                iv = rev_pw_hash[32:48]

                # encrypt new keys
                plaintext = json.dumps(channel_data).encode()
                ciphertext = AES.new(aes_key, AES.MODE_CBC, iv).encrypt(pad(plaintext,AES.block_size))

                result = {
                    "command": "KEY_BROADCAST",
                    "channel": channel,
                    "data": base64.b64encode(ciphertext).decode()
                }

                self.send_packet(client.sock,result)


    # update online users table
    def update_online_users(self):

        self.online_box.config(state=tk.NORMAL)

        self.online_box.delete("1.0", tk.END)

        self.online_box.insert(
            tk.END,
            f"{'USERNAME':<31}CHANNEL\n"
        )
        self.online_box.insert(
            tk.END,
            "-" * 38 + "\n"
        )

        with self.client_lock:
            for client in self.clients:
                username = client.username if client.username is not None else ""
                channel = client.channel if client.channel is not None else ""
                self.online_box.insert(tk.END, f"{username:<31}{channel}\n")

        self.online_box.config(state=tk.DISABLED)

    # receive helper
    def recv_packet(self, sock):
        buffer = ""

        while True:
            data = sock.recv(4096).decode()

            if not data:
                return None

            buffer += data
            if "\n" in buffer:
                line, buffer = buffer.split("\n", 1)

                if not line.strip():
                    continue
                msg = json.loads(line)
                return msg
            
    # send helper
    def send_packet(self, sock, packet):
        sock.sendall(
            (json.dumps(packet) + "\n").encode()
        )

    # log helpers
    def log_server(self, text):

        self.log_box.config(state=tk.NORMAL)

        self.log_box.insert(
            tk.END,
            text + "\n"
        )

        self.log_box.config(state=tk.DISABLED)

        self.log_box.yview(tk.END)

    def log_crypto(self, text):

        self.crypto_box.config(state=tk.NORMAL)

        self.crypto_box.insert(
            tk.END,
            text + "\n" + "\n"
        )

        self.crypto_box.config(state=tk.DISABLED)

        self.crypto_box.yview(tk.END)

    def log_channel(self, channel, text):

        box = self.channel_boxes[channel]

        box.config(state=tk.NORMAL)

        box.insert(
            tk.END,
            text + "\n"
        )

        box.config(state=tk.DISABLED)

        box.yview(tk.END)


    def on_close(self):

        self.stop_server()

        self.root.destroy()


if __name__ == "__main__":

    root = tk.Tk()
    app = Server(root)
    root.mainloop()