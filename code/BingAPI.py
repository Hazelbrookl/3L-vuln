import requests
 
# 替换为你的Bing Search API 密钥
api_key = "7de9091d219b4bbebbd5288f122e11c7"
 
def api_search(query):

    url = f"https://api.bing.microsoft.com/v7.0/search?q={query}"
    
    headers = {
        'Ocp-Apim-Subscription-Key': api_key,
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36 Edge/16.16299'
    }
    
    response = requests.get(url, headers=headers)
    
    ans = []
    if response.status_code == 200:
        response = response.json()
        for result in response['webPages']['value']:
            ans.append([result['name'], result['url']])
    else:
        ans.append(["很抱歉，搜索失败！", "https://cn.bing.com/"])
    
    return ans