import socket
import struct
import time
import pickle
import signal
import sys
import os
import threading
from collections import defaultdict


class DNSCache:
    def __init__(self):
        self.records = defaultdict(list)
        self.lock = threading.Lock()

    def add(self, domain, rtype, value, ttl):
        expiry = time.time() + ttl
        with self.lock:
            if not any(x['data'] == value for x in self.records[(domain, rtype)]):
                self.records[(domain, rtype)].append({'data': value, 'expiry': expiry})
                print(f"[+] Cached {self.type_str(rtype)} {domain} => {value} (TTL: {ttl}s)")

    def get(self, domain, rtype):
        now = time.time()
        with self.lock:
            valid = [x['data'] for x in self.records.get((domain, rtype), []) if x['expiry'] > now]
            if valid:
                print(f"[*] Cache hit: {self.type_str(rtype)} {domain} => {valid[0]}")
            return valid

    def cleanup(self):
        now = time.time()
        with self.lock:
            for key in list(self.records.keys()):
                self.records[key] = [x for x in self.records[key] if x['expiry'] > now]
                if not self.records[key]:
                    del self.records[key]

    def save_to_disk(self, filename='dns_cache.pkl'):
        self.cleanup()
        with self.lock:
            with open(filename, 'wb') as f:
                pickle.dump(dict(self.records), f)
            print(f"[*] Cache saved to {filename}")

    def load_from_disk(self, filename='dns_cache.pkl'):
        try:
            if os.path.exists(filename):
                with open(filename, 'rb') as f:
                    data = pickle.load(f)
                    with self.lock:
                        now = time.time()
                        for key, records in data.items():
                            valid_records = [r for r in records if r['expiry'] > now]
                            if valid_records:
                                self.records[key] = valid_records
                print(f"[*] Cache loaded from {filename}")
                return True
        except Exception as e:
            print(f"[!] Error loading cache: {e}")
        return False

    def type_str(self, rtype):
        types = {1: 'A', 28: 'AAAA', 2: 'NS', 12: 'PTR'}
        return types.get(rtype, f'TYPE{rtype}')


class DNSServer:
    def __init__(self, upstream='8.8.8.8', cache_file='dns_cache.pkl'):
        self.sock = None
        self.cache = DNSCache()
        self.upstream = upstream
        self.running = False
        self.cache_file = cache_file
        self.cleanup_interval = 60

        self.cache.load_from_disk(self.cache_file)

        signal.signal(signal.SIGINT, self.shutdown)
        signal.signal(signal.SIGTERM, self.shutdown)

    def start(self, host='0.0.0.0', port=53):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((host, port))
        self.sock.settimeout(1)
        self.running = True

        cleanup_thread = threading.Thread(target=self.cleanup_loop, daemon=True)
        cleanup_thread.start()

        print(f"[*] Server started on {host}:{port}")
        print(f"[*] Upstream DNS: {self.upstream}")
        print(f"[*] Cache cleanup interval: {self.cleanup_interval}s")

        while self.running:
            try:
                data, addr = self.sock.recvfrom(512)
                print(f"\n[>] Request from {addr[0]}")
                response = self.handle_query(data)
                if response:
                    self.sock.sendto(response, addr)
            except socket.timeout:
                continue
            except Exception as e:
                print(f"[!] Error: {e}")

    def cleanup_loop(self):
        while self.running:
            time.sleep(self.cleanup_interval)
            self.cache.cleanup()
            print("\n[*] Cache cleanup completed")

    def handle_query(self, data):
        try:
            if len(data) < 12:
                return None

            qid = data[:2]
            domain, qtype, qclass, offset = self.parse_question(data[12:])
            print(f"[>] Query: {self.cache.type_str(qtype)} {domain}")

            if qtype not in {1, 28, 2, 12}:  # A, AAAA, NS, PTR
                print(f"[!] Unsupported query type: {qtype}")
                return None

            if qtype == 12:
                domain = self.ip_to_ptr(domain)

            cached = self.cache.get(domain, qtype)
            if cached:
                return self.build_response(qid, domain, qtype, qclass, cached)

            print(f"[>] Forwarding {self.cache.type_str(qtype)} query for {domain}")
            resp = self.forward_query(data)
            if resp:
                self.process_response(resp)
                return resp

        except Exception as e:
            print(f"[!] Handle error: {e}")
        return None

    def parse_question(self, data):
        domain, offset = self.parse_name(data, 0)
        qtype = struct.unpack('!H', data[offset:offset + 2])[0]
        qclass = struct.unpack('!H', data[offset + 2:offset + 4])[0]
        return domain, qtype, qclass, offset + 4

    def ip_to_ptr(self, ip):
        if ip.endswith('.in-addr.arpa'):
            return ip
        parts = ip.split('.')
        if len(parts) == 4:  # IPv4
            return '.'.join(reversed(parts)) + '.in-addr.arpa'
        return ip

    def process_response(self, resp):
        try:
            pos = 12
            domain, pos = self.parse_name(resp, pos)

            # qtype + qclass
            pos += 4

            ancount = struct.unpack('!H', resp[6:8])[0]
            nscount = struct.unpack('!H', resp[8:10])[0]
            arcount = struct.unpack('!H', resp[10:12])[0]
            print(f"[<] Received {ancount} answers, {nscount} authority, {arcount} additional")

            # Answers
            self.process_rr_section(resp, pos, ancount)
            pos = self.skip_rr_section(resp, pos, ancount)

            # Authority
            self.process_rr_section(resp, pos, nscount)
            pos = self.skip_rr_section(resp, pos, nscount)

            # Additional
            self.process_rr_section(resp, pos, arcount)

        except Exception as e:
            print(f"[!] Process error: {e}")

    def process_rr_section(self, data, pos, count):
        for _ in range(count):
            if pos >= len(data):
                break
            name, pos = self.parse_name(data, pos)
            rtype, rclass, ttl, rdlength = struct.unpack('!HHIH', data[pos:pos + 10])
            pos += 10
            rdata = data[pos:pos + rdlength]
            pos += rdlength

            if rtype in {1, 28, 2, 12}:  # A, AAAA, NS, PTR
                value = self.parse_rdata(rtype, rdata, data)
                self.cache.add(name, rtype, value, ttl)
                print(f"[+] Cached {self.cache.type_str(rtype)}: {name} => {value}")

    def skip_rr_section(self, data, pos, count):
        for _ in range(count):
            if pos >= len(data):
                break
            _, pos = self.parse_name(data, pos)
            pos += 10
            rdlength = struct.unpack('!H', data[pos-2:pos])[0]
            pos += rdlength
        return pos

    def parse_rdata(self, rtype, rdata, packet):
        if rtype == 1:  # A
            return '.'.join(str(b) for b in rdata)
        elif rtype == 28:  # AAAA
            return ':'.join(f'{rdata[i:i + 2].hex()}' for i in range(0, 16, 2))
        elif rtype in {2, 12}:  # NS, PTR
            name, _ = self.parse_name(packet, 0, rdata)
            return name
        return ""

    def parse_name(self, data, offset, section=None):
        if section is None:
            section = data
        parts = []
        pos = offset
        while True:
            if pos >= len(section):
                break
            length = section[pos]
            if length == 0:
                pos += 1
                break
            if length & 0xc0 == 0xc0:
                ptr = struct.unpack('!H', section[pos:pos + 2])[0] & 0x3fff
                part, _ = self.parse_name(data, ptr)
                parts.append(part)
                pos += 2
                break
            pos += 1
            parts.append(section[pos:pos + length].decode())
            pos += length
        return '.'.join(parts), pos

    def build_response(self, qid, domain, qtype, qclass, answers):
        header = qid + b'\x81\x80\x00\x01' + struct.pack('!H', len(answers)) + b'\x00\x00\x00\x00'
        question = self.build_question(domain, qtype, qclass)
        answer_part = b''

        for answer in answers:
            if qtype == 1:  # A
                ip_bytes = bytes(map(int, answer.split('.')))
                answer_part += (b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 300, 4) + ip_bytes)
            elif qtype == 28:  # AAAA
                ip_bytes = bytes.fromhex(answer.replace(':', ''))
                answer_part += (b'\xc0\x0c' + struct.pack('!HHIH', 28, 1, 300, 16) + ip_bytes)
            elif qtype in {2, 12}:  # NS, PTR
                encoded = self.build_name(answer)
                answer_part += (
                            b'\xc0\x0c' + struct.pack('!HHIH', qtype, 1, 300, len(encoded)) + encoded)

        return header + question + answer_part

    def build_question(self, domain, qtype, qclass):
        encoded = b''
        for part in domain.split('.'):
            encoded += bytes([len(part)]) + part.encode()
        return encoded + b'\x00' + struct.pack('!HH', qtype, qclass)

    def build_name(self, domain):
        encoded = b''
        for part in domain.split('.'):
            encoded += bytes([len(part)]) + part.encode()
        return encoded + b'\x00'

    def forward_query(self, query):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(2)
            s.sendto(query, (self.upstream, 53))
            return s.recvfrom(512)[0]

    def shutdown(self, signum, frame):
        print("\n[!] Server stopping...")
        self.running = False
        self.cache.save_to_disk(self.cache_file)
        self.sock.close()
        sys.exit(0)


if __name__ == '__main__':
    print("======= DNS Proxy Server =======")
    server = DNSServer()
    server.start()
