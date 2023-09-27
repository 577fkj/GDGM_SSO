import re
import os
import datetime
import pickle
import base64
import random
import string

from Crypto.Cipher import AES
import pandas as pd
import requests
import ddddocr


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
    ocr = ddddocr.DdddOcr(show_ad=False)
    return ocr.classification(img_bytes)

class sso:
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36 Edg/117.0.2045.36'
    }

    sso_url = 'https://sfrz.gdgm.cn/authserver/login'
    sso_cap_check_url = "https://sfrz.gdgm.cn/authserver/needCaptcha.html?username={}&pwdEncrypt2=pwdEncryptSalt"
    sso_cap_img_url = "https://sfrz.gdgm.cn/authserver/captcha.html"
    sso_service_url = 'https://sfrz.gdgm.cn/authserver/login?service={}'
    session = requests.Session()

    def __init__(self, user, passwd):
        self.user = user
        self.passwd = passwd
        self.__load_cookies()
        self.__login()
        self.__save_cookies()

    def __save_cookies(self):
        with open('sso_cookies', 'wb') as f:
            pickle.dump(self.session.cookies, f)

    def __load_cookies(self):
        if os.path.exists('sso_cookies'):
            with open('sso_cookies', 'rb') as f:
                self.session.cookies.update(pickle.load(f))

    def get_service_ticket(self, service):
        response = self.session.get(self.sso_service_url.format(service), allow_redirects=False, headers=self.headers)
        if 'Location' in response.headers.keys():
            return re.findall(r'ticket=(.*)', response.headers['Location'])[0]
        else:
            raise Exception('Login failed')

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
    def __get_lt(data):
        return re.findall(r'(?<=name="lt" value=").*?(?=")', data)[0]

    @staticmethod
    def __get_execution(data):
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


class data_sheet:
    def __init__(self, name, headers):
        self.name = name
        self.headers = headers
        if os.path.exists(name):
            self.df = pd.read_csv(name)
        else:
            self.df = pd.DataFrame(columns=headers)

    def add_row(self, row):
        df_ins = pd.DataFrame([row], columns=self.headers)
        self.df = self.df.append(df_ins, ignore_index=True)

    def get_row(self, index):
        return self.df.loc[index]

    def get_last_row(self):
        return self.df.iloc[-1]

    def get_row_count(self):
        return len(self.df)

    def save(self):
        self.df.to_csv(self.name, columns=self.headers, index=False)

    def __str__(self):
        return self.df.__str__()


g_user = '' # You need to input
g_passwd = '' # You need to input
g_card_passwd = '' # You need to input
# 白云、荔湾校区 CHANGGONGGONGMAO 天河校区 MINGHANNORMAL
g_impl = '' # You need to input
# POST https://carduser.gdgm.cn/powerfee/getRoomInfo?from=&token={token}&implType={impl}
g_no = '' # You need to input
g_room = '' # You need to input


def main():
    data = data_sheet('data.csv', ['room', 'powerBalance', "diff_h", "diff", 'time'])

    # noinspection PyBroadException
    try:
        print('sso开始登录')
        sso_obj = sso(g_user, g_passwd)
    except Exception:
        print('sso登录异常')
        sso_obj = None

    card_obj = card(sso_obj, g_user, g_card_passwd)
    power_data = card_obj.get_power_balance(g_impl, g_no, g_room)

    diff_h = 0
    diff_p = 0
    if data.get_row_count() != 0:
        if power_data['lastDate'][-2:] == ".0":
            power_data['lastDate'] = power_data['lastDate'][:-2]
        t = datetime.datetime.strptime(power_data['lastDate'], '%Y-%m-%d %H:%M:%S')
        last_t = datetime.datetime.strptime(data.get_last_row()['time'], '%Y-%m-%d %H:%M:%S')
        diff_h = (t - last_t).seconds / 3600
        if diff_h == 0:
            print('数据未更新')
            print(data)
            return
        diff_p = float(power_data['powerBalance']) - data.get_last_row()['powerBalance']

    data.add_row([power_data['roomNum'], power_data['powerBalance'], diff_h, diff_p, power_data['lastDate']])
    data.save()
    print(data)


if __name__ == '__main__':
    main()
