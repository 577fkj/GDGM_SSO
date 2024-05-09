import csv
import re
import os
import datetime
import pickle
import base64
import random
import string
import time
import urllib
from urllib.parse import unquote

from Crypto.Cipher import AES
from ruamel.yaml import YAML
import requests

def pad(b: bytearray, blocksize: int) -> bytearray:
    pad_data = b''
    pad_len = blocksize - len(b) % blocksize
    if pad_len == 16 or pad_len == 0:
        return b
    for i in range(pad_len):
        pad_data += bytes([pad_len])
    return b + pad_data


def unpad(s: bytearray) -> bytearray:
    return s[:-s[-1]]

def ocr_code(img_bytes):
    try:
        import ddddocr
        ocr = ddddocr.DdddOcr(show_ad=False)
        return ocr.classification(img_bytes)
    except Exception as e:
        print('OCR识别失败', e)
        return ''

class sso:
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36 Edg/117.0.2045.36'
    }
    sso_server = 'https://sfrz.gdgm.cn'
    sso_url = sso_server + '/authserver/login'
    sso_cap_check_url = sso_server + '/authserver/needCaptcha.html?username={}&pwdEncrypt2=pwdEncryptSalt'
    sso_cap_img_url = sso_server + '/authserver/captcha.html'
    sso_service_url = sso_server + '/authserver/login?service={}'

    session = requests.Session()

    def __init__(self, user, passwd):
        self.load_cookies()
        if user and passwd:
            self.user = user
            self.passwd = passwd
            self.__login()
            self.save_cookies()


    def save_cookies(self):
        with open('sso_cookies', 'wb') as f:
            pickle.dump(self.session.cookies, f)

    def load_cookies(self):
        if os.path.exists('sso_cookies'):
            with open('sso_cookies', 'rb') as f:
                self.session.cookies.update(pickle.load(f))

    @staticmethod
    def __get_error_msg(html):
        return re.findall(r'(?<=<div id="msg" class="errors">)[\s\S]*?(?=</div>)', html)[0].replace('\n', '').replace(' ', '').replace('<h2>', '').replace('</h2>', ',').replace('<p>', '').replace('</p>', '')

    def get_service_ticket(self, service, encode = False):
        response = self.session.get(self.sso_service_url.format(service if not encode else urllib.parse.quote(service)), allow_redirects=False, headers=self.headers)
        if 'Location' in response.headers.keys():
            return re.findall(r'ticket=(.*)', response.headers['Location'])[0]
        else:
            print(response.url)
            raise Exception('Login failed', self.__get_error_msg(response.text))

    @staticmethod
    def __random_str(length):
        return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

    def __encrypt(self, data, key):
        iv = self.__random_str(16).encode('utf-8')
        cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)

        enc = base64.b64encode(
            cipher.encrypt(pad(self.__random_str(64).encode('utf-8') + data.encode('utf-8'), 16))).decode('utf-8')
        return enc

    @staticmethod
    def get_lt(data):
        return re.findall(r'(?<=name="lt" value=").*?(?=")', data)[0]

    @staticmethod
    def get_execution(data):
        return re.findall(r'(?<=name="execution" value=").*?(?=")', data)[0]

    @staticmethod
    def __get_aes(data):
        return re.findall(r'(?<=id="pwdDefaultEncryptSalt" value=").*?(?=")', data)[0]

    def __need_captcha(self):
        return requests.get(self.sso_cap_check_url.format(self.user), headers=self.headers).text == 'true'

    def __login(self):
        rsp = self.session.get(self.sso_url, allow_redirects=False, headers=self.headers)
        if rsp.status_code == 302:
            print('sso已登录')
            return
        html = rsp.text
        data = {
            'username': self.user,
            'password': self.__encrypt(self.passwd, self.__get_aes(html)),
            'lt': self.__get_lt(html),
            'dllt': 'userNamePasswordLogin',
            'execution': self.__get_execution(html),
            '_eventId': 'submit',
            'rmShown': '1'
        }
        if self.__need_captcha():
            print('需要验证码')
            img = self.session.get(self.sso_cap_img_url).content
            code = ocr_code(img)
            with open('cap.png', 'wb') as f:
                f.write(img)
            print('验证码为：', code)
            data['captchaResponse'] = code
        else:
            print('不需要验证码')
        response = self.session.post(self.sso_url, data=data, allow_redirects=False, headers=self.headers)
        if 'Location' in response.headers.keys():
            print('sso登录成功')
        else:
            # <span id="msg" class="auth_error" style="top:-19px;">您提供的用户名或者密码有误</span>
            print('sso登录失败')
            raise Exception(re.findall(r'(?<=id="msg" class="auth_error" style="top:-19px;">).*?(?=</span>)', response.text)[0])

class sso_qrcode(sso):
    sso_server = 'https://sfrz.gdgm.cn'
    sso_url = sso_server + '/authserver/login?display=qrLogin'
    sso_get_qr_code_url = sso_server + '/authserver/qrCode/get'
    sso_get_qr_img_url = sso_server + '/authserver/qrCode/code?uuid={}'
    sso_check_qr_code_url = sso_server + '/authserver/qrCode/status?uuid={}'

    uuid = ''

    def __init__(self):
        super().__init__('', '')

    def __get_qr_code_uuid(self):
        return self.session.get(self.sso_get_qr_code_url, headers=self.headers).text

    def get_qr_img(self):
        if not self.uuid:
            self.uuid = self.__get_qr_code_uuid()
        rsp = self.session.get(self.sso_get_qr_img_url.format(self.uuid), headers=self.headers)
        with open('qrcode.png', 'wb') as f:
            f.write(rsp.content)
        return rsp.content

    def check_qr_code(self):
        """
        检查二维码状态
        0: 未扫描
        2: 已扫描
        1: 已登录
        :return:
        """
        return self.session.get(self.sso_check_qr_code_url.format(self.uuid), headers=self.headers).text

    def login(self):
        response = self.session.get(self.sso_url, allow_redirects=False, headers=self.headers)
        if response.status_code == 302:
            print('sso已登录')
            return
        html = response.text
        data = {
            'lt': self.get_lt(html),
            'uuid': self.uuid,
            'dllt': 'qrLogin',
            'execution': self.get_execution(html),
            '_eventId': 'submit',
            'rmShown': '1'
        }
        response = self.session.post(self.sso_url, data=data, allow_redirects=False, headers=self.headers)
        if 'Location' in response.headers.keys():
            print('sso登录成功')
            self.save_cookies()
        else:
            print('sso登录失败')
            raise Exception('sso登录失败')

class card:
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36 Edg/117.0.2045.36'
    }
    power_url = 'https://carduser.gdgm.cn/powerfee/index'
    sso_login_url = 'https://cardsso.gdgm.cn//login?extFlag=false&needBind=false&redirectUrl=https%3A%2F%2Fcarduser.gdgm.cn%2Fpowerfee%2Findex&plat=gdgm&'
    card_sso_login_index_url = 'https://cardsso.gdgm.cn//login?extFlag=false&needBind=false&redirectUrl=https%3A%2F%2Fcarduser.gdgm.cn%2Fpowerfee%2Findex&plat=sso&'
    card_sso_login_url = 'https://cardsso.gdgm.cn/doLogin'
    card_cap_url = 'https://cardsso.gdgm.cn/captchaCode'
    power_balance_url = 'https://carduser.gdgm.cn/powerfee/getBalance'
    session = requests.Session()

    def __init__(self, sso_obj, user = '', passwd = ''):
        self.__load_cookies()
        if sso_obj is None:
            self.user = user
            self.passwd = passwd
            self.__sso_login()
        else:
            self.sso_obj = sso_obj
            self.__login()
        self.__save_cookies()

    def __save_cookies(self):
        with open('card_cookies', 'wb') as f:
            pickle.dump(self.session.cookies, f)

    def __load_cookies(self):
        if os.path.exists('card_cookies'):
            with open('card_cookies', 'rb') as f:
                self.session.cookies.update(pickle.load(f))

    def __sso_login(self):
        print('使用学工号登录')
        response = self.session.get(self.card_sso_login_index_url, headers=self.headers, allow_redirects=False)
        if response.status_code == 302:
            if 'token' in response.headers["Location"]:
                print('一卡通已登录')
            else:
                raise Exception('一卡通登录失败')
        else:
            img = self.session.get(self.card_cap_url, headers=self.headers).content
            with open('cap.png', 'wb') as f:
                f.write(img)
            code = ocr_code(img)
            print(f'验证码为 {code}')
            data = {
                "loginType": "rftSigner",
                "account": self.user,
                "password": self.passwd,
                "captchaCode": code,
                "needBind":"",
                "bindPlatform":"",
                "openid":"",
                "unionid":"",
                "alipayUserid":"",
                "ddUserid":"",
                "t": "5",
                "renter":""
            }
            response = self.session.post(self.card_sso_login_url, data=data, headers=self.headers).json()
            if response['code'] == 200:
                print('一卡通登录成功')
            else:
                print('一卡通登录失败 ' + response['msg'])


    def __login(self):
        response = self.session.get(self.sso_login_url, headers=self.headers, allow_redirects=False)
        if response.status_code == 302:
            service = re.findall(r'(?<=service=).*', response.headers["Location"])
            if len(service) > 0:
                ticket = self.sso_obj.get_service_ticket(service[0])
                response = self.session.get(self.sso_login_url + '&ticket=' + ticket, headers=self.headers)
                if 'token' in response.request.url:
                    print('一卡通登录成功')
                else:
                    print(response.status_code, response.text)
                    raise Exception('一卡通登录失败')
            else:
                if 'token' in response.headers["Location"]:
                    print('一卡通已登录')
                else:
                    raise Exception('一卡通登录失败')
        else:
            print(response.status_code, response.text)
            raise Exception('未知错误')

    def get_power_balance(self, impl, no, room):
        data = {
            "implType": impl,
            "schoolAreaNo": "",
            "buildingNo": no,
            "roomNum": room,
            "from": "",
            "token": self.session.cookies['token']
        }
        response = self.session.post(self.power_balance_url, data=data, headers=self.headers)
        return response.json()['obj']

    def get_token(self):
        return self.session.cookies['token']

class data_base:
    def __init__(self, file_path, column_headers):
        self.file_path = file_path
        self.column_headers = column_headers
        self.file_exists = os.path.isfile(file_path)

        if self.file_exists:
            self.load_csv()
        else:
            self.create_csv()

    def load_csv(self):
        with open(self.file_path, 'r', newline='') as file:
            reader = csv.DictReader(file)
            self.data = list(reader)

    def create_csv(self):
        self.data = []

    def save_csv(self):
        with open(self.file_path, 'w', newline='') as file:
            writer = csv.DictWriter(file, fieldnames=self.column_headers)
            writer.writeheader()
            writer.writerows(self.data)

    def add_row(self, row):
        if isinstance(row, dict):
            self.data.append(row)
        elif isinstance(row, list):
            self.data.append(dict(zip(self.column_headers, row)))
        else:
            raise ValueError("Invalid row format. Expected dict or list.")

    def get_row(self, index):
        return self.data[index]

    def get_last_row(self):
        return self.data[-1]

    def get_row_count(self):
        return len(self.data)

    def __str__(self):
        row_strings = [', '.join([f"{key}: {value}" for key, value in row.items()]) for row in self.data]
        if len(row_strings) > 6:
            row_strings = row_strings[:3] + ['...'] + row_strings[-3:]
        return '\n'.join(row_strings)

def load_config():
    yml = YAML(typ='safe')
    with open('config.yml', 'r', encoding='utf-8') as f:
        return yml.load(f)

def save_config(config):
    yml = YAML(typ='safe')
    with open('config.yml', 'w', encoding='utf-8') as f:
        yml.dump(config, f)

def push_wechat(url, content):
    print(content)
    print(requests.post(url, json={
        "msgtype": "text",
        "text": {
            "content": content
        }
    }).text)

def main():
    data = data_base('data.csv', ['room', 'powerBalance', "diff_h", "diff", 'time'])
    config = load_config()
    card_info = config['card']
    gdgm_info = config['gdgm']

    # noinspection PyBroadException
    try:
        print('sso开始登录')
        sso_obj = sso(gdgm_info['user'], gdgm_info['password'])
    except Exception:
        print('sso登录异常')
        sso_obj = None

    print(sso_obj)
    exit()

    card_obj = card(sso_obj, card_info['user'], card_info['password'])
    power_data = card_obj.get_power_balance(card_info['impl'], card_info['no'], card_info['room'])

    diff_h = 0
    diff_p = 0
    if data.get_row_count() != 0:
        if power_data['lastDate'][-2:] == ".0":
            power_data['lastDate'] = power_data['lastDate'][:-2]
        t = datetime.datetime.strptime(power_data['lastDate'], '%Y-%m-%d %H:%M:%S')
        last_t = datetime.datetime.strptime(data.get_last_row()['time'], '%Y-%m-%d %H:%M:%S')
        diff_h = round((t - last_t).seconds / 3600, 2)
        diff_p = round(float(power_data['powerBalance']) - float(data.get_last_row()['powerBalance']), 2)
        if diff_h == 0 and diff_p == 0:
            print('数据未更新')
            print(data)
            return

        if diff_p > 0:
            push_wechat(config['push_url'], f'电费余额增加{diff_p}度，时间：{power_data["lastDate"]}')
        else:
            tmp = ''
            now = datetime.datetime.now()
            now_day = datetime.datetime(now.year, now.month, now.day)
            for i in range(data.get_row_count() - 1, -1, -1):
                row = data.get_row(i)
                time = datetime.datetime.strptime(row['time'], '%Y-%m-%d %H:%M:%S')
                diff = float(row['diff'])

                if tmp == '' and time < now_day:
                    times = f'{(now - time).seconds // 3600}小时{(now - time).seconds % 3600 // 60}分钟'
                    now_str = now.strftime('%Y-%m-%d %H:%M:%S')
                    tmp += f'\n今日用电信息\n    用电：{round(float(row["powerBalance"]) - float(power_data["powerBalance"]), 2)}度\n    时长：{times}\n    开始时间：{time}\n    结束时间：{now_str}\n'

                if diff > 0:
                    m_datetime = datetime.datetime.strptime(data.get_last_row()['time'], '%Y-%m-%d %H:%M:%S') - time
                    times = f'{m_datetime.days}天{m_datetime.seconds // 3600}小时{m_datetime.seconds % 3600 // 60}分钟'
                    tmp += f'\n上次充值信息：\n    充值(度)：{diff}\n    电费(度)：{float(row["powerBalance"])}\n    时间：{row["time"]}\n    经过了：{times}\n    使用了(度)：{round(float(row["powerBalance"]) - float(power_data["powerBalance"]), 2)}'
                    break

            push_wechat(config['push_url'],
                        '房间号：' + power_data['roomNum'] + '\n' + '电费(度)：' + power_data['powerBalance'] + '\n' + '时间：' +
                        power_data[
                            'lastDate'] + '\n' + '电费增量(度)：' + str(diff_p) + '\n' + '时间增量(小时)：' + str(diff_h) + '\n' + tmp)

    data.add_row([power_data['roomNum'], power_data['powerBalance'], diff_h, diff_p, power_data['lastDate']])
    data.save_csv()

if __name__ == '__main__':
    main()
    # sso_obj = sso_qrcode()
    # sso_obj.get_qr_img()
    # while sso_obj.check_qr_code() != '1':
    #     time.sleep(1)
    # sso_obj.login()