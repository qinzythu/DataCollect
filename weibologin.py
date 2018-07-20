# -*- coding: utf-8 -*-
'''
@author: Zhenyu Qin
@date: 2018/7/19
@python version: 3.5.5
@function: simulate sina weibo login via Python
''' 

import re
import json
from urllib import parse
import requests
import base64
import rsa
import binascii
import time
import logging

class WeiboLogin(object):
    def __init__(self,username,password):
        self._username = username
        self._password = password
        self.session = requests.Session()
        logging.debug('initial completed!')
          
    def get_su(self):
        username_quote = parse.quote_plus(self._username)
        su = base64.b64encode(username_quote.encode("utf-8")).decode('utf-8')
        # logging.debug("su is: %s", su)
        return su
       
    def get_prelogin_args(self,su):
        params = {
            "entry": "weibo",
            "callback": "sinaSSOController.preloginCallBack",
            "rsakt": "mod",
            "checkpin": "1",
            "client": "ssologin.js(v1.4.19)",
            "su": su,
            "_": int(time.time()*1000),
        }
        try:
            response = self.session.get("https://login.sina.com.cn/sso/prelogin.php", params=params)
            prelogin_args = json.loads(re.search(r"\((?P<data>.*)\)", response.text).group("data"))
        except Exception as excep:
            prelogin_args = {}
            logging.error("Get prelogin args error:%s" % excep)
        # logging.debug("Prelogin args are: %s", prelogin_args)
        return prelogin_args
        
    def get_sp(self,servertime, nonce, pubkey):
        string = (str(servertime) + "\t" + str(nonce) + "\n" + str(self._password)).encode("utf-8")
        public_key = rsa.PublicKey(int(pubkey, 16), int("10001", 16))
        password = rsa.encrypt(string, public_key)
        sp = binascii.b2a_hex(password).decode()
        # logging.debug("sp is: %s", sp)
        return sp
        
    def get_postdata(self,su,sp,prelogin_args):
        postdata = {
            "entry": "weibo",
            "gateway": "1",
            "from": "",
            "savestate": "7",
            "qrcode_flag":'false',
            "useticket": "1",
            "pagerefer": "",
            "vsnf": "1",
            "su": su,
            "service": "miniblog",
            "servertime": prelogin_args['servertime'],
            "nonce": prelogin_args['nonce'],
            "pwencode": "rsa2",
            "rsakv": prelogin_args['rsakv'],
            "sp": sp,
            "sr": "1366*768",
            "encoding": "UTF-8",
            "prelt": "1085",
            "url": "https://www.weibo.com/ajaxlogin.php?framelogin=1&callback=parent.sinaSSOController.feedBackUrlCallBack",
            "returntype": "META"
        }
        if 'showpin' in prelogin_args.keys():
            if prelogin_args['showpin'] == 1:
                pin_url = 'https://login.sina.com.cn/cgi/pin.php?r=%s&s=0&p=%s' % (int(time.time()*1000), prelogin_args["pcid"])
                try:
                    pic = self.session.get(pin_url).content
                except Exception as excep:
                    pic = b''
                    logging.error("Get pin error:%s" % excep)
                with open("pin.png", "wb") as file_out:
                    file_out.write(pic)
                code = input("请输入验证码:")
                postdata["pcid"] = prelogin_args["pcid"]
                postdata["door"] = code
            else:
                pass
        else:
            pass
        # logging.debug("postdata is: %s",postdata)
        return postdata
        
    def Login(self):
        self.session.headers.update({'User-Agent':'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.104 Safari/537.36 Core/1.53.4482.400 QQBrowser/9.7.13001.400'})
        self.su = self.get_su()
        self.prelogin_args = self.get_prelogin_args(self.su)
        if not self.prelogin_args:
            logging.debug('Weibo Prelogin Fail!')
        else:
            self.sp = self.get_sp(self.prelogin_args["servertime"], self.prelogin_args["nonce"], self.prelogin_args["pubkey"])
            self.postdata = self.get_postdata(self.su,self.sp,self.prelogin_args)
            login_url = 'http://login.sina.com.cn/sso/login.php?client=ssologin.js(v1.4.19)'
            try:
                login_page = self.session.post(login_url, data=self.postdata)
            except Exception as excep:
                logging.error("Get login page error:%s" % excep)
                return False
            login_redirect = login_page.content.decode("GBK")
            pa = r'location\.replace\([\'"](.*?)[\'"]\)'
            redirect_url = re.findall(pa, login_redirect)[0]
            try:
                login_index = self.session.get(redirect_url)
            except Exception as excep:
                logging.error("Get login index error:%s" % excep)
                return False
            try:
                result = json.loads(re.search(r"\((?P<data>.*)\)", login_index.text).group('data'))
                if result['result']: 
                    logging.debug('Weibo Login Success!')
                    return True
                else:
                    logging.debug('Weibo Login Fail!')
                    return False
            except:
                logging.debug('Weibo Login Fail!')
                return  False
                
if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format="%(asctime)s\t%(levelname)s\t%(message)s")
    username = 'your account name'
    password = 'your password'
    A = WeiboLogin(username=username,password=password)
    A.Login()