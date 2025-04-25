import os
import pickle
import re
import base64
import random
import string
from urllib.parse import quote, unquote
from Crypto.Cipher import AES
import requests
from .utils import ocr_code, pad, unpad

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
        response = self.session.get(self.sso_service_url.format(service if not encode else quote(service)), allow_redirects=False, headers=self.headers)
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

        # encrypted_data = enc
        # encrypted_data = base64.b64decode(encrypted_data)
        # key = key.encode('utf-8')
        # iv = encrypted_data[:16]
        # cipher = AES.new(key, AES.MODE_CBC, iv)
        # decrypted_data = cipher.decrypt(encrypted_data[16:])
        # print(decrypted_data)
        # print(len(decrypted_data))
        # print(unpad(bytearray(decrypted_data[48:])).decode('utf-8'))

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
            'lt': self.get_lt(html),
            'dllt': 'userNamePasswordLogin',
            'execution': self.get_execution(html),
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
