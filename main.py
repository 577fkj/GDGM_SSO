import json
import os
import datetime
from ruamel.yaml import YAML
import pandas as pd
from sso.sso import sso
from sso.card import card
from sso.umooc import umooc
from sso.jw import jw

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


def timetable():
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

    jw_obj = jw(sso_obj, card_info['user'], card_info['password'])
    course = jw_obj.get_timetable()
    print(json.dumps(course, indent=4, ensure_ascii=False))

if __name__ == '__main__':
    timetable()
    
    # sso_obj = sso_qrcode()
    # sso_obj.get_qr_img()
    # while sso_obj.check_qr_code() != '1':
    #     time.sleep(1)
    # sso_obj.login()
