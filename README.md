# Secure Channel Application

**CS 432 Computer and Network Security** course project, Sabancı University, Spring 2026.

A client-server application for secure, authenticated message broadcast across three channels (`IF100`, `MATH101`, `SPS101`). Clients enroll, authenticate with a challenge-response protocol, and exchange encrypted messages through the server.

## Security Design

- **Enrollment:** the client sends its username, the SHA3-512 hashes of the password and the reversed password, and the selected channel, encrypted with the server's RSA-3072 public key (OAEP). Server responses are signed with RSA-PSS.
- **Authentication:** challenge-response with a 128-bit random challenge and HMAC-SHA3-512. The password itself never travels over the network.
- **Key distribution:** per-channel AES-256 keys, IVs and HMAC keys are derived from a master secret entered on the server. They are sent only to authenticated users of that channel, encrypted with AES-256-CBC and signed by the server.
- **Messaging:** messages are encrypted with AES-256-CBC and authenticated with HMAC-SHA3-512 (encrypt-then-MAC). The server relays them without decrypting; receiving clients verify and decrypt.

## Features

- Multi-client TCP server with one thread per client and lock-protected shared state.
- Persistent enrollments, and protection against the same user logging in twice.
- Tkinter GUI with separate panels for server logs, cryptographic values and each channel's traffic.

## How to Run

Requirements: Python 3 and `pycryptodome` (`pip install pycryptodome`).

1. Start the server: `python server.py`, enter IP and port, then click **Start Server**.
2. Enter a master secret for each channel and click **Generate Keys**.
3. Start clients: `python client.py`, enroll with a username, password and channel, then log in.

## Key Files

The `.pem` files are **RSA test keys provided by the course instructors** for this project. They are not used in any other system. In a real deployment, private keys would never be stored in a repository.
