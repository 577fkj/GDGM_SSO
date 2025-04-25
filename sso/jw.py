import requests
import os
import re
import pickle
from . import jw_data
from .utils import ocr_code

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

    def get_timetable(self) -> dict:
        response = self.session.get(self.jw_soc, headers=self.headers).text
        return jw_data.get_timetable(response)

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