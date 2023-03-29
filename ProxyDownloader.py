import socket, ssl
import _thread as thread
import time
import sys

HOST = "127.0.0.1"
MAX_LENGTH = 1024
ENCODING = 'utf-8'
CACHE = {}
MAX_SIZE = 10
EXPR_TIME = 20 #seconds
BLACKLIST = set()

def enable_blacklist():
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s_sock = context.wrap_socket(s, server_hostname="raw.githubusercontent.com")
    s_sock.connect(("raw.githubusercontent.com", 443))
    s_sock.send(bytes("""GET https://raw.githubusercontent.com/Ultimate-Hosts-Blacklist/Ultimate.Hosts.Blacklist/master/domains/domains2.list HTTP/1.1
Host: raw.githubusercontent.com
Accept: */*

""", "utf-8"))

    resp = b''
    i = 10
    while i > 0:
        data = s_sock.recv(MAX_LENGTH)
        if not data :
            break
        resp += data
        i -= 1

    resp = resp.split(b'\r\n\r\n')
    for line in resp[1].split(b'\n'):
        BLACKLIST.add(line)

    s_sock.close()

def remove_expired():
    expried_keys = []
    if len(CACHE) != 0:
        for key in CACHE.keys():
            if int(time.time() - CACHE.get(key)[1]) >= EXPR_TIME:
                expried_keys.append(key)
    if expried_keys:
        for key in expried_keys:
            del CACHE[key]

def proxy_thread(conn, request_data):
    request_data_arr = request_data.split(b'\r\n') 
    first_line = request_data_arr[0]

    try:
        url = first_line.split(b' ')[1]
    except Exception as e:
        print(e , "in", request_data)
    
    http_index = url.find(b'://')
    if http_index != -1:
        url = url[http_index + 3 :]    
        
    url_split = url.split(b'/')
    remote = url_split[0]
    if(remote.find(b':') != -1):
        port = int(remote.split(b':')[1].decode(ENCODING))
        remote_host = remote.split(b':')[0]
    else:
        remote_host = remote
        port = 80

    file_name = url_split[len(url_split) - 1]    

    if remote_host in BLACKLIST:
        resp = """HTTP/1.1 403 Forbidden
Content-Length: 230
Content-Type: text/html; charset=iso-8859-1
Connection: Closed

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html>
<head>
<title>403 Forbidden</title>
</head>
<body>
<h1>Forbidden</h1>
<p>You don't have permission to access this resource.</p>
</body>
</html>

"""

        resp = bytes(resp, "ISO-8859-1")
        conn.send(resp)
        conn.close()
        sys.exit()

    # IF THE REQUEST IS VALID
    try:
        print(request_data.decode(ENCODING))
    except Exception:
        print(request_data.decode("ISO-8859-1"))

    if url in CACHE.keys():
        conn.send(CACHE.get(url)[0])
        conn.close()
        print("Retrieved from proxy cache\n------------------------------------------------------------------")
        sys.exit()
    
    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remote_socket.connect((remote_host, port))
    remote_socket.send(request_data)

    print('Downloading file ', file_name.decode(ENCODING), '...')
    response_data = b''
    while True:
        chunk = remote_socket.recv(MAX_LENGTH)
        if not chunk:
            break
        response_data += chunk
    resp_time = time.time()
    
    if len(CACHE) != MAX_SIZE:
        CACHE.setdefault(url, [response_data, resp_time])

    # parse response
    response_first_line = response_data.split(b'\r\n')[0].split(b' ')
    status_code =response_first_line[1].decode(ENCODING)
    status = " ".join([status_part.decode(ENCODING) for status_part in response_first_line[2:len(response_first_line)]])
    
    print('Retrieved', status_code, status)
    response_body = ''
    if status_code == '200' and status == 'OK':
        response_body = response_data.split(b'\r\n\r\n')[1]
        if response_body:
            print("Saving file...")
            
            try:
                f = open(file_name, "wb")
                f.write(response_body)
                print('File saved')
                f.close()
            except:
                print("File could not be saved.")

    else:
        print("File could not be found on the server")     
    conn.send(response_data)
    conn.close()
    remote_socket.close()
    print("\n------------------------------------------------------------------")



def main(PORT):
    enable_blacklist()
    BLACKLIST.update([b"r3.o.lencr.org", b"ocsp.digicert.com", b"r3.o.lencr.org", b"push.services.mozilla.com", b"ocsp.pki.goog"])
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, int(PORT)))
    server_socket.listen(1) 
    print("Server is listening\n------------------------------------------------------------------")
    while True:
        conn, addr = server_socket.accept()
        request_data = conn.recv(MAX_LENGTH)
        remove_expired()
        thread.start_new_thread(proxy_thread, (conn, request_data))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("Port number missing")
    else:
        main(sys.argv[1])
    