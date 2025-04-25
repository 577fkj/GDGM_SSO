import os
import pickle
import re
import requests


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