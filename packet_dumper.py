import frida
import json
import sys
import os
import re

def find_process(pattern):
    for pid in [ pid for pid in os.listdir("/proc/") if pid.isdigit() ]:
        with open("/proc/{0}/cmdline".format(pid), "rb") as f:
            contents = f.read(2048)
            proc_argv = ""
            for n in range(0, len(contents)-1):
                if contents[n] != 0:
                    proc_argv += chr(contents[n])
                else:
                    proc_argv += " "
            if proc_argv.find(pattern) >= 0:
                return int(pid)
    return None

def on_packet_in(msg):
    packet_id = msg["id"]
    print(f"Received packet [{packet_id}] ", msg["packet"])

def on_packet_out(msg):
    packet_id = msg["id"]
    print(f"Sending packet [{packet_id}] ", msg["packet"])

def on_message(msg, data):
    if msg["type"] == "send":
        payload = msg["payload"]
        if payload["type"] == 0:
            on_packet_in(payload)
        elif payload["type"] == 1:
            on_packet_out(payload)

def main():
    pid = find_process("type=ppapi")

    if not pid:
        print("[!] Failed to find process")
        return

    print("[+] Found process", pid)

    session = frida.attach(pid)

    script = session.create_script(open("avm_script.js").read())

    script.on('message', on_message)

    script.load()

    input('[!] Press <Enter> to stop.')

    session.detach()

if __name__ == "__main__":
    main()
