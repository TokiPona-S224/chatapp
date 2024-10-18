# Toki Chat App

README for Toki: Web Chat with Ethical Backdoors

This application is a decentralised chat system that allows private and group messaging and file transfers. It includes intentional backdoors for ethical hacking exercises.

Compilation and Running Instructions:
-------------------------------------
1. Ensure you have Python 3.7 or higher installed.
2. Install the required packages:
   pip install websockets
3. Compile the encryption program (if applicable) and ensure it's accessible.
4. Run the chat server using:
   python chat_server.py
5. Open index.html in a web browser to connect as a user.

Usage Examples:
---------------
- Connect by sending a "hello" message with your user ID.
- Send a private message by sending a message with type "chat".
- Broadcast a public message by sending a message with type "public_chat".
- Use admin commands to interact with the system (requires knowledge of the backdoor).

## Client Instructions
Connect to the server using a WebSocket client. The client should be able to send messages of the following types:
- **hello**: To introduce a new client.
- **chat**: To send a private message.
- **public_chat**: To send a message to all clients.
- **encrypt_message**: To encrypt a message.
- **decrypt_message**: To decrypt a previously encrypted message.
- **get_clients**: To get a list of currently connected clients.

## Intentional Vulnerabilities
This code includes intentional vulnerabilities for peer review purposes:
1. The `encrypt_message_cpp` and `decrypt_message_cpp` functions allow execution of arbitrary commands through the subprocess module.
2. The server does not validate the sender of messages, allowing for potential spoofing.

## Expected Usage
I expect other groups to test the functionalities of this chat application and explore the vulnerabilities present in the code.
