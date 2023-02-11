import os, requests, socket, xml.etree.ElementTree as ET, threading, secrets, string
from functools import wraps
from datetime import datetime
from time import sleep
from requests import Session
from flask import Flask, request, jsonify
from pysondb import db as database


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip


timer_rotation = []
apiKey = 'qwerty'
file = 'C:\\3proxy\\bin64\\3proxy.txt'
my_global_ip = requests.get("https://ifconfig.me/ip").text
my_local_ip = get_local_ip()
alphabet = string.ascii_letters + string.digits

start_port = 7750
end_port = 7780

modem_db = database.getDb("modem.json")
timer_db = database.getDb("timer.json")
users_db = database.getDb("users.json")

app = Flask(__name__)


def api_key_authentication(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        api_key = request.json['apiKey']
        if api_key != apiKey:
            return jsonify({'error': 'Invalid API key'}), 401
        return func(*args, **kwargs)
    return wrapper


def get_headers(ip):
    data = requests.get(f"http://{ip}/api/webserver/SesTokInfo").text
    headers = {
        "Cookie": ET.fromstring(data).find("SesInfo").text,
        "__RequestVerificationToken": ET.fromstring(data).find("TokInfo").text,
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"}

    return headers


def post(ip, url, data):
    return requests.post(f"http://{ip}/{url}", data=data, headers=get_headers(ip)).text


def get(ip, url):
    return requests.get(f"http://{ip}/{url}", headers=get_headers(ip)).text


def get_signal(ip):
    rssi = int(ET.fromstring(get(ip, f"api/device/signal")).find('rssi').text.split('-')[-1].replace("dBm", ""))
    return 5 if rssi <= 60 else 4 if rssi <= 70 else 3 if rssi <= 80 else 2 if rssi <= 90 else 1


def get_modem_ip(ip):
    for i in range(2):
        try:
            session = Session()
            session.get_adapter('https://').init_poolmanager(connections=requests.adapters.DEFAULT_POOLSIZE,
                                                             maxsize=requests.adapters.DEFAULT_POOLSIZE,
                                                             source_address=(ip, 0))
            session.close()
            return session.get('https://ifconfig.me/ip').text
        except: ip = f"{ip}00"
    return None


def get_modem_info(ip):
    global_ip = get_modem_ip(ip)
    signal = get_signal(ip)
    phone = ET.fromstring(get(ip, "api/device/information")).find('Msisdn').text
    operator = ET.fromstring(get(ip, "operator.cgi")).find('FullName').text
    return signal, phone, operator, global_ip


def set_auto_mode(ip):
    post(ip, "api/net/net-mode",
         '<?xml version: "1.0" encoding="UTF-8"?><request><NetworkMode>00</NetworkMode><NetworkBand>3FFFFFFF</NetworkBand><LTEBand>7FFFFFFFFFFFFFFF</LTEBand></request>')

    while True:
        r = get(ip, 'api/net/net-mode')
        if ET.fromstring(r).find('NetworkMode').text == "00": return
        else: sleep(0.5)


def set_lte(ip):
    post(ip, "api/net/net-mode",
         '<?xml version: "1.0" encoding="UTF-8"?><request><NetworkMode>03</NetworkMode><NetworkBand>3FFFFFFF</NetworkBand><LTEBand>7FFFFFFFFFFFFFFF</LTEBand></request>')


def set_3g(ip):
    post(ip, "api/net/net-mode",
         '<?xml version: "1.0" encoding="UTF-8"?><request><NetworkMode>02</NetworkMode><NetworkBand>3FFFFFFF</NetworkBand><LTEBand>7FFFFFFFFFFFFFFF</LTEBand></request>')


def find_user(id, data):
    return [i for i, x in enumerate(data) if x == f'#{id}']


def open_port(name, port):
    os.system(f'netsh advfirewall firewall add rule name={name} dir=in action=allow protocol=TCP localport={port}')


def close_port(name, port):
    os.system(f'netsh advfirewall firewall delete rule name={name} protocol=TCP localport={port}')


class RotationByTime(threading.Thread):
    def __init__(self, ip, time):
        super().__init__()
        self.ip = ip
        self.time = time
        self.stop_flag = threading.Event()

    def run(self):
        while not self.stop_flag.is_set():
            set_3g(self.ip)
            sleep(1)
            set_lte(self.ip)
            sleep(self.time)

    def stop(self):
        self.stop_flag.set()


def start_timer():
    proxys = timer_db.getAll()
    for proxy in proxys:
        timer = RotationByTime(modem_db.getById(proxy['modem_id'])['localIp'], proxy['time'])
        timer_rotation.append(timer)
        timer.start()


@app.route('/api/status', methods=['POST'])
@api_key_authentication
def api_status():
    return jsonify({'status': 'ok'}), 200


@app.route('/api/get/allModems', methods=['POST'])
@api_key_authentication
def get_all_modems():
    try:
        modem_list = {}
        x = 0
        for i in range(1, 254):
            if not os.system(f"ping -n 1 192.168.{i}.1"):
                modem_list.update({x: f'192.168.{i}.1'})
                x += 1
        return jsonify(modem_list), 200
    except: return jsonify({'error': 'An error has occurred'}), 404


@app.route('/api/get/portRange', methods=['POST'])
@api_key_authentication
def get_port_range():
    return jsonify({'startPort': start_port, 'endPort': start_port}), 200


@app.route('/api/create/modem', methods=['POST'])
@api_key_authentication
def create_modem():
    content = request.json
    ip = content['localIp']
    try:
        if os.system(f"ping -n 1 {ip}"):
            return jsonify({'error': 'There is no modem with this ip'}), 401
        else:
            id = modem_db.add({'localIp': ip})
            if id:
                try:
                    signal, phone, operator, global_ip = get_modem_info(ip)
                    return jsonify({'id': id, 'signal': signal, 'phone': phone, 'operator': operator, 'globalIp': global_ip}), 200
                except: return jsonify({'error': 'Сheck if the modem is working'}), 404
            else: return jsonify({'error': 'Failed to create modem'}), 404
    except: return jsonify({'error': 'An error has occurred'}), 404


@app.route('/api/get/modem/info', methods=['POST'])
@api_key_authentication
def modem_get_info():
    modem = modem_db.getById(request.json['id'])
    if modem:
        try:
            signal, phone, operator, global_ip = get_modem_info(modem['localIp'])
            return jsonify({'signal': signal, 'phone': phone, 'operator': operator, 'globalIp': global_ip}), 200
        except: return jsonify({'error': 'Failed to get info from modem'}), 404
    else: return jsonify({'error': 'No modem with this id'}), 404


@app.route('/api/get/modem/signal', methods=['POST'])
@api_key_authentication
def modem_get_signal():
    modem = modem_db.getById(request.json['id'])
    if modem:
        try:
            signal = get_signal(modem['localIp'])
            return jsonify({'signal': signal}), 200
        except:
            return jsonify({'error': 'Failed to get signal from modem'}), 404
    else:
        return jsonify({'error': 'No modem with this id'}), 404


@app.route('/api/get/modem/ip', methods=['POST'])
@api_key_authentication
def modem_get_ip():
    modem = modem_db.getById(request.json['id'])
    if modem:
        try:
            ip = get_modem_ip(modem['localIp'])
            if ip: return jsonify({'globalIp': ip}), 200
            else: return jsonify({'globalIp': None}), 200
        except: return jsonify({'error': 'Failed to get global IP from modem'}), 404
    else: return jsonify({'error': 'No modem with this id'}), 404


@app.route("/api/add/rotationByTimer", methods=['POST'])
@api_key_authentication
def add_rotation_by_timer():
    content = request.json
    id = content['id']
    time = content['time']
    modem = modem_db.getById(request.json['id'])
    if modem:
        try:
            timer_db.add({'modem_id': id, 'time': time})

            timer = RotationByTime(modem['localIp'], time)
            timer_rotation.append(timer)
            timer.start()

            return jsonify({'status': 'ok'}), 200
        except: return jsonify({'error': 'Failed to add rotation by timer'}), 404
    else: return jsonify({'error': 'No modem with this id'}), 404


@app.route("/api/delete/rotationByTimer", methods=['POST'])
@api_key_authentication
def delete_rotation_by_timer():
    content = request.json
    id = content['id']
    modem = modem_db.getById(request.json['id'])
    if modem:
        try:
            ip = modem['localIp']
            timer = timer_db.getByQuery({'modem_id': id})[0]

            for timer in timer_rotation:
                if timer.ip == ip and timer.time == timer['time']:
                    timer.stop()
                    sleep(5)
                    set_lte(ip)

            timer_db.deleteById(timer['id'])
            return jsonify({'status': 'ok'}), 200
        except: return jsonify({'error': 'Failed to delete rotation by timer'}), 404
    else: return jsonify({'error': 'No modem with this id'}), 404


@app.route('/api/reboot/modem', methods=['POST'])
@api_key_authentication
def reboot_modem():
    modem = modem_db.getById(request.json['id'])
    if modem:
        try:
            post(modem['localIp'], "api/device/control", '<?xml version: "1.0" encoding="UTF-8"?><request><Control>1</Control></request>')
            return jsonify({'status': 'ok'}), 200
        except: return jsonify({'error': 'Failed to reboot modem'}), 404
    else: return jsonify({'error': 'No modem with this id'}), 404


@app.route('/api/modem/send/ussd', methods=['POST'])
@api_key_authentication
def send_ussd():
    content = request.json
    code = content['code']
    modem = modem_db.getById(content['id'])
    if modem:
        try:
            ip = modem['localIp']
            set_auto_mode(ip)
            post(ip, "api/ussd/send",
                 f'<?xml version: "1.0" encoding="UTF-8"?><request><content>{code}</content><codeType>CodeType</codeType><timeout></timeout></request>')

            while True:
                if ET.fromstring(get(ip, "api/ussd/status")).find('result').text == "0":  break
                else:  sleep(0.5)

            answer = ET.fromstring(get(ip, "api/ussd/get")).find('content').text
            set_lte(ip)

            return jsonify({'answer': answer}), 200
        except: return jsonify({'error': 'Failed to send USSD'}), 404
    else: return jsonify({'error': 'No modem with this id'}), 404


@app.route('/api/modem/send/sms', methods=['POST'])
@api_key_authentication
def send_sms():
    content = request.json

    sms = content['text']
    phone = content['phone']
    modem = modem_db.getById(content['id'])
    now = datetime.now()
    now_str = now.strftime("%Y-%m-%d %H:%M:%S")

    if modem:
        try:
            ip = modem['localIp']
            set_auto_mode(ip)
            post(ip, "api/sms/send-sms",
                 f'''<?xml version: "1.0" encoding="UTF-8"?>
                                  <request>
                                  <Index>-1</Index>
                                  <Phones><Phone>{phone}</Phone></Phones>
                                  <Sca></Sca>
                                  <Content>{sms}</Content>
                                  <Length>{len(sms)}</Length>
                                  <Reserved>1</Reserved>
                                  <Date>{now_str}</Date>
                                  </request>''')
            status = ''
            while True:
                root = ET.fromstring(get(ip, "api/sms/send-status"))
                if root.find('FailPhone').text: status = 'fail'
                elif root.find('SucPhone').text: status = 'ok'
                elif status: break
                else: sleep(1)

            set_lte(ip)

            return jsonify({'status': status}), 200
        except: return jsonify({'error': 'Failed to send SMS'}), 404
    else: return jsonify({'error': 'No modem with this id'}), 404


@app.route('/api/check/modem', methods=['POST'])
@api_key_authentication
def check_modem():
    modem = modem_db.getById(request.json['id'])
    if modem:
        try:
            if os.system(f"ping -n 1 {modem['localIp']}"): return jsonify({'status': 'fail'}), 200
            else: return jsonify({'status': 'ok'}), 200
        except: return jsonify({'error': 'Failed to check modem'}), 404
    else: return jsonify({'error': 'No modem with this id'}), 404


@app.route('/api/delete/modem', methods=['POST'])
@api_key_authentication
def delete_modem():
    id = request.json['id']
    modem = modem_db.getById(id)
    if modem:
        try:
            with open(file, 'r') as f:
                data = f.read()

            data = list(filter(None, data.split('\n')))
            for user in users_db.getByQuery({'modem_id': id}):
                users_db.deleteById(user['id'])
                lines = find_user(user['id'], data)
                del data[lines[0]:lines[1] + 1]

            with open(file, 'w') as f:
                f.write("".join(f'{i}\n' for i in data))

            modem_db.deleteById(id)
            return jsonify({'status': 'ok'}), 200
        except: return jsonify({'error': 'Failed to delete modem and users'}), 404
    else: return jsonify({'error': 'No modem with this id'}), 404


@app.route('/api/create/user', methods=['POST'])
@api_key_authentication
def create_user():
    content = request.json

    id = content['id']
    login = content['login']
    password = content['password']
    http_port = content['httpPort']
    socks_port = content['socksPort']

    modem = modem_db.getById(id)
    if modem:
        try:
            id = users_db.add({'modem_id': id, 'login': login, 'password': password, 'httpPort': http_port, 'socksPort': socks_port})
            local_ip = modem['localIp']

            with open(file, 'a') as f:
                f.write(f"\n#{id}\n"
                        f"auth strong\n"
                        f"users {login}:CL:{password}\n"
                        f"allow {login}\n"
                        f"proxy -n -a -p{http_port} -i{my_local_ip} -e{local_ip}00\n"
                        f"socks -n -a -p{socks_port} -i{my_local_ip} -e{local_ip}00\n"
                        f"flush\n"
                        f"#{id}")

            return jsonify({'id': id}), 200
        except: return jsonify({'error': 'Failed to create user'}), 404
    else: return jsonify({'error': 'No modem with this id'}), 404


@app.route('/api/change/user', methods=['POST'])
@api_key_authentication
def change_user():
    content = request.json

    id = content['id']
    new_login = content['newLogin']
    new_password = content['newPassword']
    new_http_port = content['newHttpPort']
    new_socks_port = content['newSocksPort']

    user = users_db.getById(id)
    if user:
        try:
            users_db.updateById(id, {'login': new_login, 'password': new_password, 'httpPort': new_http_port, 'socksPort': new_socks_port})

            with open(file, 'r') as f:  data = f.read()
            data = list(filter(None, data.split('\n')))
            lines = find_user(id, data)

            modem = modem_db.getById(user['modem_id'])
            for line in [lines[0] + i for i, x in enumerate(data[lines[0]:lines[1] + 1])]:
                if 'users' in data[line]: data[line] = f'users {new_login}:CL:{new_password}'
                elif 'allow' in data[line]: data[line] = f'allow {new_login}'
                elif 'proxy -' in data[line]: data[line] = f'proxy -n -a -p{new_http_port} -i{my_local_ip} -e{modem["localIp"]}00'
                elif 'socks -' in data[line]: data[line] = f'socks -n -a -p{new_socks_port} -i{my_local_ip} -e{modem["localIp"]}00'

            with open(file, 'w') as f: f.write("".join(f'{i}\n' for i in data))
            return jsonify({'status': 'ok'}), 200
        except: return jsonify({'error': 'Failed to change user'}), 404
    else: return jsonify({'error': 'No user with this id'}), 404


@app.route('/api/user/enable', methods=['POST'])
@api_key_authentication
def enable_user():
    content = request.json
    id = content['id']
    user = users_db.getById(id)
    if user:
        try:
            open_port(id, user['httpPort'])
            open_port(id, user['httpPort'])
            for ip in [my_local_ip, my_global_ip]:
                proxies = {
                    "http": f"http://{user['login']}:{user['password']}@{ip}:{user['httpPort']}",
                    "https": f"http://{user['login']}:{user['password']}@{ip}:{user['httpPort']}",
                }
                try:  requests.get("https://ifconfig.me/ip", proxies=proxies)
                except:
                    close_port(id, user['httpPort'])
                    close_port(id, user['httpPort'])
                    return jsonify({'error': "Proxy not working"}), 404
            return jsonify({'status': 'ok'}), 200
        except: return jsonify({'error': 'Failed to enable user'}), 404
    else: return jsonify({'error': 'No user with this id'}), 404


@app.route('/api/user/disable', methods=['POST'])
@api_key_authentication
def disable_user():
    content = request.json
    id = content['id']
    new_login = ''.join(secrets.choice(alphabet) for i in range(8))
    new_password = ''.join(secrets.choice(alphabet) for i in range(8))
    user = users_db.getById(id)
    if user:
        try:
            with open(file, 'r') as f: data = f.read()
            data = list(filter(None, data.split('\n')))
            users_db.updateById(id, {'login': new_login, 'password': new_password})

            lines = find_user(id, data)
            if not lines: return 'Not found', 404

            lines = [lines[0] + i for i, x in enumerate(data[lines[0]:lines[1] + 1]) if 'users' in x or 'allow' in x]
            data[lines[0]] = f'users {new_login}:CL:{new_login}'
            data[lines[1]] = f'allow {new_login}'

            with open(file, 'w') as f:
                f.write("".join(f'{i}\n' for i in data))

            close_port(id, user['httpPort'])
            close_port(id, user['socksPort'])

            return jsonify({'newLogin': new_login,  'newPassword': new_password}), 200
        except: return jsonify({'error': 'Failed to disable user'}), 404
    else: return jsonify({'error': 'No user with this id'}), 404


@app.route('/api/delete/user', methods=['POST'])
@api_key_authentication
def delete_user():
    id = request.json['id']
    user = users_db.getById(id)
    if user:
        try:
            with open(file, 'r') as f: data = f.read()

            data = list(filter(None, data.split('\n')))
            lines = find_user(user['id'], data)
            del data[lines[0]:lines[1] + 1]
            users_db.deleteById(user['id'])

            with open(file, 'w') as f: f.write("".join(f'{i}\n' for i in data))

            return jsonify({'status': 'ok'}), 200
        except: return jsonify({'error': 'Failed to delete user'}), 404
    else: return jsonify({'error': 'No user with this id'}), 404


@app.route('/api/reboot/pc', methods=['POST'])
@api_key_authentication
def reboot_pc():
    try:
        os.system("shutdown -r -t 5")
        return jsonify({'status': 'ok'}), 200
    except: return jsonify({'error': 'Failed to reboot PC'}), 404


@app.route('/api/reboot/3proxy', methods=['POST'])
@api_key_authentication
def reboot_3proxy():
    try:
        os.system('net stop 3proxy')
        sleep(3)
        os.system('net start 3proxy')
        return jsonify({'status': 'ok'}), 200
    except: return jsonify({'error': 'Failed to reboot 3Proxy'}), 404


@app.route("/tkproxy_<id>", methods=['GET'])
def rotation(id):
    def rotation_ip(ip):
        set_3g(ip)
        sleep(1)
        set_lte(ip)

    user = users_db.getById(id)
    if user:
        modem = modem_db.getById(user['modem_id'])
        if modem:
            try:
                rotation_ip(modem['localIp'])
                return jsonify({'status': 'ok'}), 200
            except: return jsonify({'error': 'An error has occurred'}), 404
        else: return jsonify({'error': 'An error has occurred'}), 404
    else: return jsonify({'error': 'Invalid URL'}), 404


if __name__ == "__main__":
    start_timer()
    app.run()
