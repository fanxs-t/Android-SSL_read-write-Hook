# -*- coding:utf-8
# Author : Fanxs
# 2019-12-16

# Refer to https://github.com/google/ssl_logger/blob/master/ssl_logger.py

import frida
import sys
import os
import signal
import socket
import struct
import hexdump
import time
import random
import csv
import queue
import re

application = ["cn.missfresh.application"]
# the path of pcap and html logging file
pcap = "C:\\Users\\lenovo\\Desktop\\log.pcap"
htmlf = "C:\\Users\\lenovo\\Desktop\\log.html"

'''
Decrypts and logs a process's SSL traffic.
Hooks the functions SSL_read() and SSL_write() in a given process send the decrypted data to the console.
'''
_FRIDA_SCRIPT = r"""
  /**
  * define global objects.
  */ 
  var SSL_get_fd, SSL_get_session, SSL_SESSION_get_id, getpeername, getsockname, ntohs, ntohl, addresses;
  var necessary_functions = [
      "SSL_get_fd", 
      "SSL_get_session", 
      "SSL_SESSION_get_id",
      "getpeername",
      "getsockname",
      "ntohs",
      "ntohl"
  ];
  console.log("[*] Start the Script.");

   /**
   * Initializes 'addresses' dictionary and NativeFunctions.
   */
  function initializeGlobals()
  {
    addresses = {};
    var resolver = new ApiResolver("module");
    var exps = [
      ["*libssl*",
        ["SSL_read", "SSL_write", "SSL_get_fd", "SSL_get_session",
        "SSL_SESSION_get_id"]],
      ["*libc*",
        ["getpeername", "getsockname", "ntohs", "ntohl"]]
      ];
    for (var i = 0; i < exps.length; i++)
    {
      var lib = exps[i][0];
      var names = exps[i][1];

      for (var j = 0; j < names.length; j++)
      {
        var name = names[j];
        var matches = resolver.enumerateMatchesSync("exports:" + lib + "!" +
          name);
        if (matches.length == 0)
        {
          throw "Could not find " + lib + "!" + name;
        }
        else if (matches.length != 1)
        {
          // Sometimes Frida returns duplicates.
          var address = 0;
          var s = "";
          var duplicates_only = true;
          for (var k = 0; k < matches.length; k++)
          {
            if (s.length != 0)
            {
              s += ", ";
            }
            s += matches[k].name + "@" + matches[k].address;
            if (address == 0)
            {
              address = matches[k].address;
            }
            else if (!address.equals(matches[k].address))
            {
              duplicates_only = false;
            }
          }
          if (!duplicates_only)
          {
            throw "More than one match found for " + lib + "!" + name + ": " +
              s;
          }
        }
        addresses[name] = matches[0].address;
      }
    }
    for(var index in necessary_functions){
        var key = necessary_functions[index];
        console.log("   * Function: " + key + ", value: " + addresses[key]);
    }
    SSL_get_fd = new NativeFunction(addresses["SSL_get_fd"], "int", ["pointer"]);
    SSL_get_session = new NativeFunction(addresses["SSL_get_session"], "pointer", ["pointer"]);
    SSL_SESSION_get_id = new NativeFunction(addresses["SSL_SESSION_get_id"], "pointer", ["pointer", "pointer"]);
    getpeername = new NativeFunction(addresses["getpeername"], "int", ["int", "pointer", "pointer"]);
    getsockname = new NativeFunction(addresses["getsockname"], "int", ["int", "pointer", "pointer"]);
    ntohs = new NativeFunction(addresses["ntohs"], "uint16", ["uint16"]);
    ntohl = new NativeFunction(addresses["ntohl"], "uint32", ["uint32"]);
  }
  initializeGlobals();

  /**
   * Returns a dictionary of a sockfd's "src_addr", "src_port", "dst_addr", and
   * "dst_port".
   * @param {int} sockfd The file descriptor of the socket to inspect.
   * @param {boolean} isRead If true, the context is an SSL_read call. If
   *     false, the context is an SSL_write call.
   * @return {dict} Dictionary of sockfd's "src_addr", "src_port", "dst_addr",
   *     and "dst_port".
   */
  function getPortsAndAddresses(sockfd, isRead)
  {
    var message = {};

    var addrlen = Memory.alloc(4);
    var addr = Memory.alloc(16);

    var src_dst = ["src", "dst"];
    for (var i = 0; i < src_dst.length; i++)
    {
      Memory.writeU32(addrlen, 16);
      if ((src_dst[i] == "src") ^ isRead)
      {
        getsockname(sockfd, addr, addrlen);
      }
      else
      {
        getpeername(sockfd, addr, addrlen);
      }
      message[src_dst[i] + "_port"] = ntohs(Memory.readU16(addr.add(2)));
      message[src_dst[i] + "_addr"] = ntohl(Memory.readU32(addr.add(4)));
    }

    return message;
  }

  /**
   * Get the session_id of SSL object and return it as a hex string.
   * @param {!NativePointer} ssl A pointer to an SSL object.
   * @return {dict} A string representing the session_id of the SSL object's
   *     SSL_SESSION. For example,
   *     "59FD71B7B90202F359D89E66AE4E61247954E28431F6C6AC46625D472FF76336".
   */
  function getSslSessionId(ssl)
  {
    var session = SSL_get_session(ssl);
    if (session == 0)
    {
      return 0;
    }
    var len = Memory.alloc(4);
    var p = SSL_SESSION_get_id(session, len);
    len = Memory.readU32(len);

    var session_id = "";
    for (var i = 0; i < len; i++)
    {
      // Read a byte, convert it to a hex string (0xAB ==> "AB"), and append
      // it to session_id.
      session_id +=
        ("0" + Memory.readU8(p.add(i)).toString(16).toUpperCase()).substr(-2);
    }

    return session_id;
  }

  Interceptor.attach(addresses["SSL_read"],
  {
    onEnter: function (args)
    {
      var message = getPortsAndAddresses(SSL_get_fd(args[0]), true);
      message["ssl_session_id"] = getSslSessionId(args[0]);
      message["function"] = "SSL_read";
      this.message = message;
      this.buf = args[1];
    },
    onLeave: function (retval)
    {
      retval |= 0; // Cast retval to 32-bit integer.
      if (retval <= 0)
      {
        return;
      }
      send(this.message, Memory.readByteArray(this.buf, retval));
    }
  });

  Interceptor.attach(addresses["SSL_write"],
  {
    onEnter: function (args)
    {
      var message = "Requests."
      var message = getPortsAndAddresses(SSL_get_fd(args[0]), false);
      message["ssl_session_id"] = getSslSessionId(args[0]);
      message["function"] = "SSL_write";
      send(message, Memory.readByteArray(args[1], parseInt(args[2])));
    },
    onLeave: function (retval){}
  });
  """

# ssl_session[<SSL_SESSION id>] = (<bytes sent by client>,
#                                  <bytes sent by server>)
ssl_sessions = {}
requests_queue_list = {}  # queue.Queue(20)
response = ""
response_flag = False             # True if any response was received

def log_pcap(pcap_file, ssl_session_id, function, src_addr, src_port,
               dst_addr, dst_port, data):
    """Writes the captured data to a pcap file.

    Args:
      pcap_file: The opened pcap file.
      ssl_session_id: The SSL session ID for the communication.
      function: The function that was intercepted ("SSL_read" or "SSL_write").
      src_addr: The source address of the logged packet.
      src_port: The source port of the logged packet.
      dst_addr: The destination address of the logged packet.
      dst_port: The destination port of the logged packet.
      data: The decrypted packet data.
    """
    t = time.time()

    if ssl_session_id not in ssl_sessions:
      ssl_sessions[ssl_session_id] = (random.randint(0, 0xFFFFFFFF),
                                      random.randint(0, 0xFFFFFFFF))
    client_sent, server_sent = ssl_sessions[ssl_session_id]

    if function == "SSL_read":
        # Responses/ ACK = SEQ + 1
        seq, ack = (server_sent, client_sent + 1)
    else:
        # Requests
        seq, ack = (client_sent, server_sent)

    for writes in (
        # PCAP record (packet) header
        ("=I", int(t)),                        # Timestamp seconds
        ("=I", int((t * 1000000) % 1000000)),  # Timestamp microseconds
        ("=I", 40 + len(data)),           # Number of octets saved
        ("=i", 40 + len(data)),           # Actual length of packet
        # IPv4 header
        (">B", 0x45),                     # Version and Header Length
        (">B", 0),                        # Type of Service
        (">H", 40 + len(data)),           # Total Length
        (">H", 0),                        # Identification
        (">H", 0x4000),                   # Flags and Fragment Offset
        (">B", 0xFF),                     # Time to Live
        (">B", 6),                        # Protocol
        (">H", 0),                        # Header Checksum
        (">I", src_addr),                 # Source Address
        (">I", dst_addr),                 # Destination Address
        # TCP header
        (">H", src_port),                 # Source Port
        (">H", dst_port),                 # Destination Port
        (">I", seq),                      # Sequence Number
        (">I", ack),                      # Acknowledgment Number
        (">H", 0x5018),                   # Header Length and Flags
        (">H", 0xFFFF),                   # Window Size
        (">H", 0),                        # Checksum
        (">H", 0)):                       # Urgent Pointer
        pcap_file.write(struct.pack(writes[0], writes[1]))
    pcap_file.write(data)

    if function == "SSL_read":
        remaining_length = requests_queue_list[dst_port]["Response"][0]
        process_response(dst_port, data, remaining_length)
    else:
        req = str(data)[2:-1]
        if(src_port not in requests_queue_list.keys()):
            requests_queue_list[src_port] = {"Request":queue.Queue(20), "Response":[0, ""]}
        requests_queue_list[src_port]["Request"].put(req)
        
    if function == "SSL_read":
        server_sent += len(data)
    else:
        client_sent += len(data)
    ssl_sessions[ssl_session_id] = (client_sent, server_sent)

def process_response(port, raw_response, remaining_length):
    ''' 
    Process request and response, Log the traffic data to html file
    '''
    res = str(raw_response)[2:-1]
    if re.match("HTTP/\d\.\d \d+", res):
        if(remaining_length != 0):
            requests_queue_list[port]["Response"][0] = 0
            response = requests_queue_list[port]["Response"][1]
            return html_log_request(port, res)

        content_length = re.search("\\r\\nContent-Length:\s(\d+)\\r\\n", res)
        if content_length == None:
            # Usually for status 304, 302, 500, 204...
            # Response Transmission Complete
            requests_queue_list[port]["Response"][0] = 0
            return html_log_request(port, res)
        body_start = raw_response.find(b'\r\n\r\n')
        length = len(raw_response[body_start + 4:])
        if length >= content_length:
            requests_queue_list[port]["Response"][0] = 0
            return html_log_request(port, res)
        else:
            requests_queue_list[port]["Response"][0] = content_length-length
            requests_queue_list[port]["Response"][1] += res
    else:
        if(remaining_length <= 0):
            return None
        length = len(raw_response)
        if length >= remaining_length:
            res = requests_queue_list[port]["Response"][1] + res
            requests_queue_list[port]["Response"][0] = 0
            return html_log_request(port, res)
        else:
            requests_queue_list[port]["Response"][0] = remaining_length -length
            requests_queue_list[port]["Response"][1] += res

def html_log_request(port, response):
    request = requests_queue_list[port]["Request"].get().replace("\\r\\n", "\n")
    response = response.replace("\\r\\n", "\n")
    html_file.write(td.format(Request=request, Response=response))
    html_file.flush()

def on_message(message, data):
    if message["type"] == "error":
      print(message)
      os.kill(os.getpid(), signal.SIGTERM)
      return
    if len(data) == 0:
      return
    p = message["payload"]
    src_addr = socket.inet_ntop(socket.AF_INET, struct.pack(">I", p["src_addr"]))
    dst_addr = socket.inet_ntop(socket.AF_INET, struct.pack(">I", p["dst_addr"]))
    print("SSL Session: " + p["ssl_session_id"])
    print("[%s] %s:%d --> %s:%d" % (p["function"], src_addr, p["src_port"], dst_addr, p["dst_port"]))
    log_pcap(pcap_file, p["ssl_session_id"], p["function"], p["src_addr"], p["src_port"], p["dst_addr"], p["dst_port"], data)

# pcap logging
pcap_file = open(pcap, "wb", 0)
for writes in (
        ("=I", 0xa1b2c3d4),     # Magic number
        ("=H", 2),              # Major version number
        ("=H", 4),              # Minor version number
        ("=i", time.timezone),  # GMT to local correction
        ("=I", 0),              # Accuracy of timestamps
        ("=I", 65535),          # Max length of captured packets
        ("=I", 228)):           # Data link type (LINKTYPE_IPV4)
    pcap_file.write(struct.pack(writes[0], writes[1]))

# html logging
html_file = open(htmlf, "w")
html = '''
<html><head><style>
table {font-family: arial, sans-serif;  border-collapse: collapse;  width: 100%;  table-layout:fixed;}
td, th {  border: 1px solid #dddddd;  text-align: left;  padding: 8px; }
tr:nth-child(even) { background-color: #dddddd;}
#longer{height:80px;overflow:auto;word-break: normal;}
#long{overflow:hidden;word-break: normal;}
</style></head>  
<body><table style="width:100%"><tr><th>Requests</th><th>Responses</th></tr>
'''
html_file.write(html)
td = "<tr id=\"long\"><th VALIGN=\"TOP\" id=\"longer\"><pre>{Request}</pre></th><th VALIGN=\"TOP\" id=\"longer\"><pre>{Response}</pre></th></tr>"

# frida hooking
device = frida.get_device_manager().enumerate_devices()[-1]
pid = device.spawn(application)
session = device.attach(pid)
device.resume(pid)
print("[*] Press Ctrl+C to stop logging.")
script = session.create_script(_FRIDA_SCRIPT)
script.on('message', on_message)
script.load()

try:
    sys.stdin.read()
except KeyboardInterrupt:
    pass
session.detach()
pcap_file.close()
html_file.close()
exit(0)
