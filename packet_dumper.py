import frida
import json
import sys
import os
import re
import psutil

preamble =  '''
const packet_sender_id  = 27006;
const packet_handler_id = 27013;
const darkbot_pattern = "01 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 02 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00"
'''

if sys.platform.startswith("linux"):
    preamble +=  '''
const stringify_pattern          = "55 48 89 d0 48 89 f5 4d 89 c1 49 89 c8 48 89 c1 53 48 81 ec 98 00 00 00"

const offsets= {
    method_list : 0x180,
    ns_list : 0x190
}
'''
elif sys.platform.startswith("win32"):
    preamble += '''
const stringify_pattern = "40 53 48 81 ec c0 00 00 00 48 8b 84 24 f0 00 00 00 48 8b da 48 8b 51 10 48 89 44 24 28"
const offsets = {
    method_list : 0x148,
    ns_list : 0x188
}
'''

def find_flash_process():
    for proc in psutil.process_iter(["pid", "ppid", "cmdline"]):
        if proc.info["cmdline"] and "--type=ppapi" in proc.info["cmdline"]:
            return(proc.info["pid"])
    return None

def on_packet_in(msg):
    packet_id = msg["id"]
    packet_name = msg["name"]
    print(f"Received packet {packet_name} [{packet_id}]")
    print(json.dumps(msg["packet"], indent=4))

def on_packet_out(msg):
    packet_id = msg["id"]
    packet_name = msg["name"]
    print(f"Sending packet {packet_name} [{packet_id}]")
    print(json.dumps(msg["packet"], indent=4))

def on_message(msg, data):
    if msg["type"] == "send":
        payload = msg["payload"]
        if payload["type"] == 0:
            on_packet_in(payload)
        elif payload["type"] == 1:
            on_packet_out(payload)
    else:
        print(msg)

def main():
    pid = find_flash_process()

    if not pid:
        print("[!] Failed to find process")
        return

    print("[+] Found process", pid)

    try:
        session = frida.attach(pid)
    except frida.ProcessNotRespondingError as e:
        print(e)
        print("Try launching the chromium process with --no-sandbox")
        sys.exit(-1)

    script = session.create_script(preamble + open("avm_script.js").read())

    script.on('message', on_message)

    script.load()

    input('[!] Press <Enter> to stop.')

    session.detach()

if __name__ == "__main__":
    main()
