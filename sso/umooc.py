import os
import pickle
import re
import urllib.parse
import requests

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
