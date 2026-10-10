import base64
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
from Crypto.Util.Padding import pad, unpad



class Client:

    # hardcoded channels
    CHANNELS = ["IF100", "MATH101", "SPS101"]

    def __init__(self):

        # networking
        self.sock = None
        self.connected = False
        self.authenticated = False

        # channel keys
        self.channel_keys_received = False
        self.channel_key = None
        self.channel_iv = None
        self.channel_hmac_key = None

        # user info
        self.username = None
        self.channel = None
        self.broadcast_hash = None

        #loading RSA keys
        with open("server_enc_dec_pub.pem", "rb") as f:
            self.rsa_key = RSA.import_key(f.read())

        with open("server_sign_verify_pub.pem", "rb") as f:
            self.sign_key = RSA.import_key(f.read())

        # GUI
        self.root = tk.Tk()
        self.root.title("Client Client")
        self.root.geometry("1300x750")

        self.setup_ui()

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        self.root.mainloop()

    # UI setup
    def setup_ui(self):

        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_columnconfigure(1, weight=3)
        self.root.grid_rowconfigure(0, weight=1)

        self.left_frame = tk.Frame(self.root, padx=10, pady=10)
        self.left_frame.grid(row=0, column=0, sticky="ns")

        self.right_frame = tk.Frame(self.root, padx=10, pady=10)
        self.right_frame.grid(row=0, column=1, sticky="nsew")

        self.create_connection_frame()
        self.create_auth_frame()
        self.create_chat_frame()
        self.create_logs()

    # connection frame setup
    def create_connection_frame(self):

        frame = tk.LabelFrame(self.left_frame, text="Connection")
        frame.pack(fill="x", pady=5)

        tk.Label(frame, text="IP").pack(anchor="w")

        self.ip_entry = tk.Entry(frame)
        self.ip_entry.insert(0, "127.0.0.1")
        self.ip_entry.pack(fill="x", pady=2)

        tk.Label(frame, text="Port").pack(anchor="w")

        self.port_entry = tk.Entry(frame)
        self.port_entry.insert(0, "5050")
        self.port_entry.pack(fill="x", pady=2)

        self.connect_btn = tk.Button(
            frame,
            text="Connect",
            command=self.connect
        )

        self.connect_btn.pack(fill="x", pady=5)

        self.disconnect_btn = tk.Button(
            frame,
            text="Disconnect",
            command=self.disconnect,
            state=tk.DISABLED
        )

        self.disconnect_btn.pack(fill="x")

    # authentication UI setup
    def create_auth_frame(self):

        frame = tk.LabelFrame(self.left_frame, text="Authentication")
        frame.pack(fill="x", pady=5)

        tk.Label(frame, text="Username").pack(anchor="w")

        self.username_entry = tk.Entry(frame)
        self.username_entry.pack(fill="x", pady=2)

        tk.Label(frame, text="Password").pack(anchor="w")

        self.password_entry = tk.Entry(frame, show="*")
        self.password_entry.pack(fill="x", pady=2)

        tk.Label(frame, text="Channel").pack(anchor="w")

        self.channel_combo = ttk.Combobox(
            frame,
            values=self.CHANNELS,
            state="readonly"
        )

        self.channel_combo.current(0)
        self.channel_combo.pack(fill="x", pady=2)

        self.enroll_btn = tk.Button(
            frame,
            text="Enroll",
            command=self.enroll,
            state=tk.DISABLED
        )

        self.enroll_btn.pack(fill="x", pady=(10, 2))

        self.login_btn = tk.Button(
            frame,
            text="Login",
            command=self.login,
            state=tk.DISABLED
        )

        self.login_btn.pack(fill="x")

    # chat UI setup
    def create_chat_frame(self):

        frame = tk.LabelFrame(self.right_frame, text="Chat")
        frame.pack(fill="both", expand=True, pady=5)

        self.chat_box = scrolledtext.ScrolledText(
            frame,
            state=tk.DISABLED
        )

        self.chat_box.pack(fill="both", expand=True)

        bottom = tk.Frame(frame)
        bottom.pack(fill="x", pady=5)

        self.message_entry = tk.Entry(bottom)
        self.message_entry.pack(
            side=tk.LEFT,
            fill="x",
            expand=True,
            padx=(0, 5)
        )

        self.send_btn = tk.Button(
            bottom,
            text="Send",
            command=self.send_message,
            state=tk.DISABLED
        )

        self.send_btn.pack(side=tk.RIGHT)

    # log frames setup
    def create_logs(self):

        frame = tk.LabelFrame(self.right_frame, text="Logs")
        frame.pack(fill="both", expand=True, pady=5)

        frame.grid_rowconfigure(0, weight=1)
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_columnconfigure(1, weight=1)

        self.log_box = scrolledtext.ScrolledText(
            frame,
            state=tk.DISABLED
        )
        self.log_box.grid(row=0, column=0, sticky="nsew")

        crypto_frame = tk.LabelFrame(frame, text="Crypto Logs")
        crypto_frame.grid(row=0, column=1, sticky="nsew", padx=5)

        self.crypto_box = scrolledtext.ScrolledText(
            crypto_frame,
            state=tk.DISABLED
        )
        self.crypto_box.pack(fill="both", expand=True)

    # connect to server
    def connect(self):

        # print RSA keys as crypto logs
        self.crypto_log(f"Server RSA Public Key: {self.rsa_key.export_key().decode('utf-8')}")
        self.crypto_log(f"Server Signature RSA Public Key: {self.sign_key.export_key().decode('utf-8')}")
        
        if self.connected:
            return

        ip = self.ip_entry.get().strip()

        try:
            port = int(self.port_entry.get().strip())
        except:
            messagebox.showerror(
                "Error",
                "Invalid port"
            )
            return

        try:
            self.sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM
            )
            self.sock.connect((ip, port))
            self.connected = True

            # lock/unlcok UI elements
            self.connect_btn.config(state=tk.DISABLED)
            self.disconnect_btn.config(state=tk.NORMAL)
            self.enroll_btn.config(state=tk.NORMAL)
            self.login_btn.config(state=tk.NORMAL)

            self.log("Connected to server")

        except Exception as e:

            messagebox.showerror(
                "Connection Error",
                str(e)
            )

    # disconnect function to handle disconnection and UI changes
    def disconnect(self):

        self.connected = False
        self.authenticated = False

        try:
            self.sock.close()
            self.connected = False
        except:
            pass

        self.connect_btn.config(state=tk.NORMAL)
        self.disconnect_btn.config(state=tk.DISABLED)
        self.enroll_btn.config(state=tk.DISABLED)
        self.login_btn.config(state=tk.DISABLED)
        self.send_btn.config(state=tk.DISABLED)

        self.log("Disconnected")


    # enroll function
    def enroll(self):

        if not self.connected or not self.sock:
            messagebox.showerror("Error","Not connected to server")
            return

        # get info
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        reverse_password = password[::-1]
        channel = self.channel_combo.get()

        if not username or not password:
            messagebox.showerror("Error","Username/password required")
            return

        self.log("Preparing enrollment request")

        # hash pw/rev_pw
        pw_hash = SHA3_512.new(
            data=password.encode()
        ).hexdigest()
        rev_pw_hash = SHA3_512.new(
            data=reverse_password.encode()
        ).hexdigest()
        # used hexdigest for transportation reasons and easier to store in JSON

        #logging
        self.crypto_log(f"Password Hash: {pw_hash}")
        self.crypto_log(f"Reverse Password Hash: {rev_pw_hash}")
        
        # concentrate into one
        plaintext = (
            username.encode()
            + b"|"
            + pw_hash.encode()
            + b"|"
            + rev_pw_hash.encode()
            + b"|"
            + channel.encode()
        )

        # check for length to prevent RSA length issues
        if len(plaintext) > 342:
            messagebox.showerror("Error", "Enrollment message too large")
            return

        # encryot with RSA
        ciphertext = PKCS1_OAEP.new(self.rsa_key).encrypt(plaintext)

        # prepare the packet
        packet = {
            "command": "ENROLL",
            "data": base64.b64encode(ciphertext).decode("utf-8")
        }

        self.crypto_log(f"Encrypted enrollment data (by RSA): {ciphertext.hex()}")

        self.send_json(packet)
        self.log("Enrollment request sent")

        # wait for response
        response = self.recv_json()
        if response is None:
            self.log("Server disconnected")
            self.disconnect()
            return

        # check for signature and verify it
        if "signature" not in response:
            self.log("Missing signature")

            messagebox.showerror("Enrollment","Unsigned response rejected")
            return
        try:
            # retrieve sign/payload
            signature = base64.b64decode(response.get("signature"))
            payload = response.get("payload")

            # hash the payload
            hash_to_verify = SHA3_512.new(json.dumps(payload,sort_keys=True).encode("utf-8"))

            # verify
            verifier = PKCS1_PSS.new(self.sign_key)
            verifier.verify(hash_to_verify,signature)

            # log
            self.crypto_log(f"Received signature: {signature.hex()}")
            self.log("Signature verified")

        # if verification unsuccessful
        except Exception as e:
            self.log(f"Signature verification failed: {e}")
            messagebox.showerror("Enrollment","Invalid server signature")
            return

        # if verified, process the payload
        command = payload.get("command")

        # guard against incorrect command
        if command != "ENROLL_RESULT":
            self.log("Unexpected response")
            return

        status = payload.get("status")

        self.log(f"Enrollment result: {status}")

        # remove password for reentry
        self.password_entry.delete(0, tk.END)

        # check status and display the result
        if status == "success":
            messagebox.showinfo("Enrollment", "Enrollment successful")
        else:
            if "reason" in payload:
                self.log(f"Enrollment Failed: {payload.get("reason")}")
            else:
                self.log(f"Enrollment Failed: unknown reason")
            messagebox.showerror("Enrollment"," Enrollment failed")


    # login function
    def login(self):

        # connection check, safeguard
        if not self.connected or not self.sock:
            messagebox.showerror("Error","Not connected to server")
            return

        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()

        if not username or not password:
            messagebox.showerror("Error","Username/password required")
            return

        self.username = username

        # preparing and sending login request
        self.log("Sending login request")
        packet = {
            "command": "LOGIN",
            "username": username
        }
        self.send_json(packet)

        # receive challenge
        challenge_packet = self.recv_json()

        # safety checks
        if challenge_packet is None:
            self.log("Server disconnected")
            self.disconnect()
            return
        if challenge_packet.get("command") == "LOGIN_FAILED":
            # if reason included, display it
            if "reason" not in challenge_packet:
                self.log("Authentication failed")
            else:
                self.log(f"Authentication failed: {challenge_packet.get("reason")}")
            return
        elif challenge_packet.get("command") != "LOGIN_CHALLENGE":
            self.log("Unexpected response")
            return

        self.log("Challenge received")

        # compute response HMAC
        challenge = base64.b64decode(challenge_packet.get("challenge"))
        self.crypto_log(f"Challenge: {challenge.hex()}")

        pw_hash = SHA3_512.new(data=password.encode()).digest()
        rev_pw_hash = SHA3_512.new(data=password[::-1].encode()).digest()
        self.broadcast_hash = rev_pw_hash

        # use pw hash for hmac key
        hmac_key = pw_hash[0:32]
        self.crypto_log(f"Challenge HMAC Key: {hmac_key.hex()}")

        # prepare the hmac
        hmac_response = CryptoHMAC.new(hmac_key,digestmod=SHA3_512)
        hmac_response.update(challenge)

        # prepare the packet
        response_packet = {
            "command": "LOGIN_RESPONSE",
            "username": username,
            "response": hmac_response.hexdigest()
        }

        # sent it
        self.send_json(response_packet)

        self.log("Challenge response sent")
        self.crypto_log(f"Challenge HMAC Response: {hmac_response.hexdigest()}")

        # receive the result packet
        result_packet = self.recv_json()

        # safeguard
        if result_packet is None:
            self.log("Server disconnected")
            self.disconnect()
            return
        
        # check the signature
        if "signature" not in result_packet:
            self.log("Missing signature")

            messagebox.showerror("Login","Unsigned response rejected")
            return

        try:
            # try to verifiy
            signature = base64.b64decode(result_packet.get("signature"))

            payload = base64.b64decode(result_packet.get("payload"))
            hash_to_verify = SHA3_512.new(payload)
            verifier = PKCS1_PSS.new(self.sign_key)
            verifier.verify(hash_to_verify,signature)

            self.log("Signature verified")
            self.crypto_log(f"Login ACK Signature: {signature.hex()}")

        except Exception as e: # if not verified
            self.log(f"Signature verification failed: {e}")
            messagebox.showerror("Login","Invalid server signature")
            return 

        # decrypt the response with AES
        # retrieve the keys from hashes
        aes_key = rev_pw_hash[0:32]
        iv = rev_pw_hash[32:48]

        self.crypto_log(f"Login ACK AES Key: {aes_key.hex()}")
        self.crypto_log(f"Login ACK AES IV: {iv.hex()}")

        try:
            # dec with AES
            plaintext_padded = AES.new(aes_key, AES.MODE_CBC, iv).decrypt(payload)
            plaintext = unpad(plaintext_padded,AES.block_size)
            # load plaintext to a json obj
            result_packet = json.loads(plaintext.decode())
        except (ValueError, KeyError, json.JSONDecodeError): 
            # when password is incorrect, AES will fail
            self.log("Login failed or corrupted response")
            messagebox.showerror("Login Failed", "Incorrect username/password")
            self.disconnect()
            return

        # retrieve result command
        command = result_packet.get("command")

        if command == "LOGIN_SUCCESS":
            # if successful check for keys

            self.authenticated = True
            self.channel = result_packet.get("channel")
            self.log("Authentication successful")

            channel_data = result_packet.get("channel_data")

            # check for "None" keys. If a key is "None", that means that key is not generated yet
            if channel_data["aes_key"] is not None:
                self.channel_key = bytes.fromhex(channel_data["aes_key"])
                self.channel_iv = bytes.fromhex(channel_data["iv"])
                self.channel_hmac_key = bytes.fromhex(channel_data["hmac_key"])
            
            # a bool value for checking whether valid keys are received
            if self.channel_key is None:
                self.channel_keys_received = False
            else:
                self.channel_keys_received = True

            # logging
            self.crypto_log(f"Channel AES Key:  {self.channel_key.hex() if self.channel_key else 'None'}")
            self.crypto_log(f"Channel AES IV:   {self.channel_iv.hex() if self.channel_iv else 'None'}")
            self.crypto_log(f"Channel HMAC Key: {self.channel_hmac_key.hex() if self.channel_hmac_key else 'None'}")

            # lock buttons
            self.enroll_btn.config(state=tk.DISABLED)
            self.login_btn.config(state=tk.DISABLED)
            self.send_btn.config(state=tk.NORMAL)
            # delete pass
            self.password_entry.delete(0, tk.END)

            # after successful login, start listening
            threading.Thread(target=self.listen,daemon=True).start()

            messagebox.showinfo("Login","Authentication successful")

        # login unsuccessful
        elif command == "LOGIN_FAILED":

            # if reason included, display it
            if "reason" not in result_packet:
                self.log("Authentication failed")
            else:
                self.log(f"Authentication failed: {result_packet.get("reason")}")

            # rm pass
            self.password_entry.delete(0, tk.END)

            messagebox.showerror("Login","Authentication failed")

            self.disconnect()

        # if unexpected command is received
        else:
            self.log("Unexpected login result")

    # send message functions, also encrypts it
    def send_message(self):

        # safeguards
        if not self.authenticated:
            return
        # check if valid keys are received, else dont send
        if not self.channel_keys_received:
            messagebox.showerror("Channel Error", "Channel keys are not received")
            return

        # retrieve the message and clear entrybox
        text = self.message_entry.get().strip()
        if not text:
            return
        self.message_entry.delete(0, tk.END)

        self.log("Encrypting message")

        # enc with AES with channel key + iv
        ciphertext = AES.new(self.channel_key,AES.MODE_CBC,iv=self.channel_iv).encrypt(pad(text.encode(),AES.block_size))

        # create HMAC with channel hmac key
        hmac = CryptoHMAC.new(self.channel_hmac_key,digestmod=SHA3_512)
        hmac.update(ciphertext)

        # create packet and send it
        packet = {
            "command": "MESSAGE",
            "sender": self.username,
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "hmac": hmac.hexdigest()
        }
        self.send_json(packet)

        self.log("Message sent")

    # listener thread function
    def listen(self):

        self.log("Entered listen status")

        buffer = ""
        try:

            while self.connected and self.authenticated and self.sock:
                data = self.sock.recv(4096).decode()

                if not data:
                    break

                buffer += data

                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)

                    try:
                        msg = json.loads(line)
                        self.message_handler(msg) # call handler function

                    except Exception as e:
                        self.log(f"Invalid packet: {e}")

        except Exception as e:
            self.log(f"Listener error: {e}")

        self.disconnect()

    # message handler, handles incoming messages and key broadcasts
    def message_handler(self, msg):

        command = msg.get("command")

        # if a message is received
        if command == "MESSAGE":

            # retreive sender
            sender = msg.get("sender")

            self.log(f"Message received from {sender}")

            try:

                # verify hmac first
                ciphertext = base64.b64decode(msg.get("ciphertext"))
                received_hmac = msg.get("hmac")

                hmac_verify = CryptoHMAC.new(self.channel_hmac_key,digestmod=SHA3_512)
                hmac_verify.update(ciphertext)
                hmac_verify.hexverify(received_hmac)

                self.log("Message HMAC verified")

                # decrypt the message with channel key + iv
                plaintext_padded = AES.new(self.channel_key, AES.MODE_CBC, iv=self.channel_iv).decrypt(ciphertext)
                plaintext = unpad(plaintext_padded,AES.block_size).decode()

                # display the message
                self.display_message(sender, plaintext)

            except Exception as e: # verification unsuccessful and other errors caught
                self.log(f"Message rejected: {e}")
        
        # key broadcast handler
        elif command == "KEY_BROADCAST":
            try:
                self.log("Key broadcast received")

                # use reverse pw hash to retrieve AES key + iv
                aes_key = self.broadcast_hash[0:32]
                iv = self.broadcast_hash[32:48]

                # decrypt the data
                plaintext_padded = AES.new(aes_key, AES.MODE_CBC, iv=iv).decrypt(base64.b64decode(msg.get("data")))
                plaintext = unpad(plaintext_padded,AES.block_size)
                channel_data = json.loads(plaintext)
                
                # if new keys are not None, use them
                if channel_data["aes_key"] is not None:
                    # convert from transport hex to bytes
                    self.channel_key = bytes.fromhex(channel_data["aes_key"])
                    self.channel_iv = bytes.fromhex(channel_data["iv"])
                    self.channel_hmac_key = bytes.fromhex(channel_data["hmac_key"])
                
                # if new keys are None, ignore them
                if self.channel_key is None:
                    self.channel_keys_received = False
                else:
                    # if new keys valid, enable message sending
                    self.channel_keys_received = True

                # logging
                if self.channel_key is not None:
                    self.log("New keys received")
                    self.crypto_log(f"New Channel AES Key:  {self.channel_key.hex() if self.channel_key else 'None'}")
                    self.crypto_log(f"New Channel AES IV:   {self.channel_iv.hex() if self.channel_iv else 'None'}")
                    self.crypto_log(f"New Channel HMAC Key: {self.channel_hmac_key.hex() if self.channel_hmac_key else 'None'}")
                
            except Exception:
                traceback.print_exc()

        # unknown command handler
        else:
            self.log(f"Unknown command: {command}")

    # send_json helper
    def send_json(self, data):

        try:
            self.sock.sendall(
                (json.dumps(data) + "\n").encode()
            )

        except:
            self.disconnect()

    # chat display formatter
    def display_message(self, sender, text):

        self.chat_box.config(state=tk.NORMAL)

        self.chat_box.insert(
            tk.END,
            f"{sender}: {text}\n"
        )

        self.chat_box.config(state=tk.DISABLED)
        self.chat_box.yview(tk.END)

    # regular server logger
    def log(self, text):

        self.log_box.config(state=tk.NORMAL)

        self.log_box.insert(
            tk.END,
            text + "\n"
        )
        self.log_box.config(state=tk.DISABLED)
        self.log_box.yview(tk.END)

    # cryptographic info logger
    def crypto_log(self, text):

        self.crypto_box.config(state=tk.NORMAL)

        self.crypto_box.insert(
            tk.END,
            text + "\n" + "\n"
        )

        self.crypto_box.config(state=tk.DISABLED)
        self.crypto_box.yview(tk.END)

    # receiver helper
    def recv_json(self):

        buffer = ""

        try:
            while True:

                data = self.sock.recv(4096).decode()

                if not data:
                    return None

                buffer += data

                if "\n" in buffer:

                    line, buffer = buffer.split("\n", 1)

                    return json.loads(line)

        except (ConnectionResetError, ConnectionAbortedError, OSError):
            return None


    def on_close(self):

        self.disconnect()

        self.root.destroy()

if __name__ == "__main__":

    Client()