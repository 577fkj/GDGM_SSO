import json
import re
import os
import datetime
import pickle
import base64
import random
import string
import urllib
from urllib.parse import unquote

from Crypto.Cipher import AES
from ruamel.yaml import YAML
import pandas as pd
import requests
import ddddocr
import time

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

class umooc:
    headers = {
        'User-Agent': 'Mozilla/5.0 (Linux; Android 11; Redmi K30 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Mobile Safari/537.36'
    }
    sso_url = 'https://umooc.gdgm.cn/meol/homepage/common/sso_login.jsp'
    sso_login_url = 'https://umooc.gdgm.cn/meol/homepage/common/sso_login.jsp'
    sso_param = [
        ';jsessionid={}?ticket={}',
        '?ticket={}',
    ]
    umooc_index = 'https://umooc.gdgm.cn/meol/index.do'
    umooc_my = 'https://umooc.gdgm.cn/meol/personal.do'
    umooc_login = 'https://umooc.gdgm.cn/meol/loginCheck.do'
    session = requests.Session()
    def __init__(self, sso_obj, user = '', passwd = ''):
        self.__load_cookies()
        if sso_obj is None:
            self.user = user
            self.passwd = passwd
            self.__login()
        else:
            self.sso_obj = sso_obj
            self.__sso_login()
        self.__save_cookies()

    def __save_cookies(self):
        with open('umooc_cookies', 'wb') as f:
            pickle.dump(self.session.cookies, f)

    def __load_cookies(self):
        if os.path.exists('umooc_cookies'):
            with open('umooc_cookies', 'rb') as f:
                self.session.cookies.update(pickle.load(f))

    @staticmethod
    def __get_jsessionid(url):
        print(url)
        return re.findall(r'(?<=jsessionid=).*?(?=$)', url)[0]

    @staticmethod
    def __get_login_token(data):
        # <input type="hidden" name="logintoken" value="xxxxxxxxxx">
        return re.findall(r'(?<=name="logintoken" value=").*?(?=")', data)[0]

    def __is_login(self):
        response = self.session.get(self.umooc_my, headers=self.headers)
        if response.text.find('重新登录') != -1:
            return False
        else:
            return True

    @staticmethod
    def __get_error_msg(data):
        return re.findall(r'(?<=<div class="loginerror_mess">)[\d\D]*?(?=</div>)', data)[0].replace('\n', '').replace('<br>', '').replace('\r', '').replace('\t', '').replace(' ', '')

    def __sso_login(self):
        if self.__is_login():
            print('慕课已登录')
            return
        response = self.session.get(self.sso_url, headers=self.headers, allow_redirects=False)
        if response.status_code == 302:
            url = response.headers["Location"]
            service = re.findall(r'(?<=service=).*', response.headers["Location"])
            if len(service) > 0:
                url = urllib.parse.unquote(service[0])
            ticket = self.sso_obj.get_service_ticket(self.sso_login_url, True)
            if 'jsessionid' in url:
                param = self.sso_param[0].format(self.__get_jsessionid(url), ticket)
            else:
                param = self.sso_param[1].format(ticket)
            response = self.session.get(self.sso_login_url + param, headers=self.headers)

            if self.umooc_my in response.url:
                print('慕课登录成功')
            else:
                print(response.status_code, response.text)
                raise Exception('慕课登录失败')
        else:
            print(response.status_code, response.text)
            raise Exception('未知错误')

    def __login(self):
        if self.__is_login():
            print('慕课已登录')
            return
        response = self.session.get(self.umooc_index, headers=self.headers, allow_redirects=False)
        login_token = self.__get_login_token(response.text)
        data = {
            "logintoken": login_token,
            "IPT_LOGINUSERNAME": self.user,
            "IPT_LOGINPASSWORD": self.passwd
        }
        response = self.session.post(self.umooc_login, data=data, headers=self.headers)
        if self.umooc_my in response.url:
            print('慕课登录成功')
        else:
            print(response.status_code, response.text)
            raise Exception('慕课登录失败', self.__get_error_msg(response.text))

class jw:
    headers = {
        'User-Agent': 'Mozilla/5.0 (Linux; Android 11; Redmi K30 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Mobile Safari/537.36'
    }
    session = requests.Session()
    jw_url = 'https://jw.gdgm.cn'
    service = jw_url + '/jsxsd/sso.jsp'
    jw_index = '/jsxsd/framework/xsMain.jsp'
    jw_login_code = jw_url + '/Logon.do?method=logon&flag=sess'
    jw_login = jw_url + '/Logon.do?method=logon'
    jw_cap_url = jw_url + '/verifycode.servlet'
    jw_check_session = jw_url + '/jsxsd/framework/blankPage.jsp'
    jw_soc = jw_url + '/jsxsd/xskb/xskb_list.do'

    def __init__(self, sso_obj, user = '', passwd = ''):
        self.__load_cookies()
        if sso_obj is None:
            self.user = str(user)
            self.passwd = str(passwd)
            self.__login()
        else:
            self.sso_obj = sso_obj
            self.__sso_login()

    def __save_cookies(self):
        with open('jw_cookies', 'wb') as f:
            pickle.dump(self.session.cookies, f)

    def __load_cookies(self):
        if os.path.exists('jw_cookies'):
            with open('jw_cookies', 'rb') as f:
                self.session.cookies.update(pickle.load(f))

    def __check_session(self):
        response = self.session.get(self.jw_check_session, headers=self.headers)
        if len(response.text) == 0:
            return True
        return False

    def __get_course_info(self, data):
        data = data.split('--')
        # remove empty string
        data = list(filter(None, data))
        course_info = []
        for s in data:
            pattern = r'(.+?)\s*((?:\d+-\d+,?)+)\(周\)(.+)'
            matches = re.findall(pattern, s)
            if len(matches) > 0:
                # 解析周
                weeks = []
                for week in matches[0][1].split(','):
                    week = week.split('-')
                    if len(week) == 1:
                        weeks.append(int(week[0]))
                    else:
                        weeks.extend(range(int(week[0]), int(week[1]) + 1))
                course_info.append([
                    matches[0][0],
                    weeks,
                    matches[0][2]
                ])
        return course_info

    def get_soc(self):
        response = self.session.get(self.jw_soc, headers=self.headers).text
        data = re.findall(r'(class="kbcontent".*?>|<br>)(.*?)<font title=\'老师\'>(.*?)</font>', response)
        teachers = {}
        for i in range(len(data)):
            teachers[data[i][1].replace('<br/>', '')] = data[i][2]
        data = pd.read_html(response)[0].to_dict()
        keys = list(data.keys())
        # 星期
        week = keys[1:]
        # 课程时间
        time = list(data[keys[0]].values())
        tips_index = time.index('备注:')
        # 课程
        course = {
            'tips': data[week[0]][tips_index],
            'course': {}
        }
        for i in range(len(week)):
            c = data[week[i]].values()
            # 去除Nan
            c = [x if not pd.isna(x) else '' for x in c]
            for j in range(len(c)):
                # 去除备注
                if j == tips_index:
                    continue
                # 处理课程
                if c[j] != '':
                    info = self.__get_course_info(c[j])
                    for x in info:
                        for w in x[1]:
                            if w not in course['course']:
                                course['course'][w] = {}
                            if time[j] not in course['course'][w]:
                                course['course'][w][time[j]] = []
                            course['course'][w][time[j]].append({
                                'name': x[0],
                                'teacher': teachers[x[0]],
                                'room': x[2]
                            })
        return course

    @staticmethod
    def __get_msg(data):
        return re.findall(r'(?<=<li class="input_li" id="showMsg" style="color: red; margin-bottom: 0;">)[\d\D]*?(?=</li>)', data)[0].replace('\n', '').replace('<br>', '').replace('\r', '').replace('\t', '').replace(' ', '').replace('&nbsp;', '')

    @staticmethod
    def encrypt(data, code):
        datas = code.split('#')
        scode = datas[0]
        sxh = datas[1]
        encode = ''
        for i in range(len(data)):
            if i < 20:
                encode += data[i] + scode[0:int(sxh[i])]
                scode = scode[int(sxh[i]):]
            else:
                encode += data[i:]
                break
        return encode

    @staticmethod
    def decrypt(encode, code):
        datas = code.split('#')
        scode = datas[0]
        sxh = datas[1]
        decode = ''
        offset = 0
        for i in range(len(sxh)):
            decode += encode[offset]
            offset += int(sxh[i]) + 1
            if offset >= len(encode):
                break
        if offset > len(sxh):
            decode += encode[offset:]
        return decode

    def __login(self):
        if self.__check_session():
            print('教务已登录')
            return
        cap = self.session.get(self.jw_cap_url, headers=self.headers).content
        with open('cap.png', 'wb') as f:
            f.write(cap)
        cap_code = ocr_code(cap)
        print('验证码：', cap_code)
        code = self.session.get(self.jw_login_code, headers=self.headers).text
        if code == 'no':
            print('验证码加密失败')
            return
        data = {
            'userAccount': self.user,
            'userPassword': self.passwd,
            'RANDOMCODE': cap_code,
            'encoded': jw.encrypt(self.user + '%%%' + self.passwd, code),
        }
        response = self.session.post(self.jw_login, allow_redirects=False, data=data, headers=self.headers)
        if response.status_code == 302:
            print('教务登录成功')
        else:
            msg = self.__get_msg(response.text)
            if msg == '验证码错误!!':
                print('验证码错误 重试')
                self.__login()
                return
            print(response.status_code, response.text)
            raise Exception('教务登录失败', self.__get_msg(response.text))

    def __sso_login(self):
        if self.__check_session():
            print('教务已登录')
            return
        ticket = self.sso_obj.get_service_ticket(self.service, True)
        response = self.session.get(self.service + '?ticket=' + ticket, headers=self.headers)
        if self.jw_index in response.url:
            print('教务登录成功')
        else:
            print(response.status_code, response.url, response.text)
            raise Exception('教务登录失败')

class data_base:
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

def load_config():
    yml = YAML(typ='safe')
    with open('config.yml', 'r', encoding='utf-8') as f:
        return yml.load(f)

def save_config(config):
    yml = YAML(typ='safe')
    with open('config.yml', 'w', encoding='utf-8') as f:
        yml.dump(config, f)


def main():
    data = data_base('data.csv', ['room', 'powerBalance', "diff_h", "diff", 'time'])
    config = load_config()
    card_info = config['card']
    gdgm_info = config['gdgm']
    umooc_info = config['umooc']
    jw_info = config['jw']

    # noinspection PyBroadException
    try:
        print('sso开始登录')
        sso_obj = sso(gdgm_info['user'], gdgm_info['password'])
    except Exception:
        print('sso登录异常')
        sso_obj = None

    # umooc_obj = umooc(sso_obj, umooc_info['user'], umooc_info['password'])
    # jw_obj = jw(sso_obj, jw_info['user'], jw_info['password'])
    # print(jw_obj.get_soc())


    card_obj = card(sso_obj, card_info['user'], card_info['password'])
    power_data = card_obj.get_power_balance(card_info['impl'], card_info['no'], card_info['room'])

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
    
    # sso_obj = sso_qrcode()
    # sso_obj.get_qr_img()
    # while sso_obj.check_qr_code() != '1':
    #     time.sleep(1)
    # sso_obj.login()
