import requests
import json
import csv

keys = ['cve-id', 'published', 'modified', 'vulnStatus', 'descriptions', 'cvss3.1AV', 'cvss3.1AC', 'cvss3.1PR', 'cvss3.1UI', 
        'cvss3.1S', 'cvss3.1C', 'cvss3.1I', 'cvss3.1A', 'exploitabilityScore', 'impactScore', 'baseScore', 'baseSeverity', 'cwe-type']

def get_nvd_data_from_date(start_date, end_date):
    # 构建请求的 URL
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0/?pubStartDate={start_date}&pubEndDate={end_date}"
    
    # 发送 GET 请求
    response = requests.get(url)
    
    # 检查响应状态码
    if response.status_code == 200:
        # 如果响应成功，返回 JSON 数据
        return response.json()
    else:
        # 如果响应失败，打印错误信息并返回 None
        print(f"Failed to fetch NVD data. Status code: {response.status_code}")
        return None
    
def get_nvd_data_from_id(id):
    # 构建请求的 URL
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0/?cveId={id}"
    
    # 发送 GET 请求
    max_retries = 10
    # 使用循环和 try-except 结构来重试函数
    for i in range(max_retries):
        try:
            response = requests.get(url)
            if response.status_code == 200:
                # 如果响应成功，返回 JSON 数据
                return response.json()
            else:
                continue
        except Exception as e:
            if i == max_retries - 1:
                raise Exception("重试次数已达上限，函数仍然失败")
            continue  # 如果是其他异常，继续重试
    
    print(f"Failed to fetch NVD data. Status code: {response.status_code}")
    return None
    
def read_id_from_cnnvd(filename):
    id_list = []
    with open(filename, 'r', newline='', encoding='utf-8') as csvfile:
    # 使用 csv.reader 读取 CSV 文件内容
        reader = csv.reader(csvfile)
        next(reader)

        for row in reader:
            if row[8]:
                id_list.append(row[8])
    return id_list
    
# def save_json_to_file(data, filename):
#     # 将数据写入文件
#     with open(filename, 'w', encoding='utf-8') as file:
#         json.dump(data, file, indent=4)

def data_processing(raw_data, target_file):
    with open(target_file, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        
        # 写入CSV头部
        writer.writerow(keys)
        
        # 遍历XML元素并写入CSV
        for vuln in raw_data:
            if vuln is None:
                writer.writerow()
                continue
            data = []
            data.append(vuln.get('cve').get('id'))
            data.append(vuln.get('cve').get('published'))
            data.append(vuln.get('cve').get('lastModified'))
            data.append(vuln.get('cve').get('vulnStatus'))
            data.append(vuln.get('cve').get('descriptions')[0].get('value'))
            cvss31 = vuln.get('cve').get('metrics').get('cvssMetricV31')
            if cvss31 is not None:
                data.append(cvss31[0].get('cvssData').get('attackVector'))
                data.append(cvss31[0].get('cvssData').get('attackComplexity'))
                data.append(cvss31[0].get('cvssData').get('privilegesRequired'))
                data.append(cvss31[0].get('cvssData').get('userInteraction'))
                data.append(cvss31[0].get('cvssData').get('scope'))
                data.append(cvss31[0].get('cvssData').get('confidentialityImpact'))
                data.append(cvss31[0].get('cvssData').get('integrityImpact'))
                data.append(cvss31[0].get('cvssData').get('availabilityImpact'))
                data.append(cvss31[0].get('exploitabilityScore'))
                data.append(cvss31[0].get('impactScore'))
                data.append(cvss31[0].get('cvssData').get('baseScore'))
                data.append(cvss31[0].get('cvssData').get('baseSeverity'))
            else:
                data.append(None)
                data.append(None)
                data.append(None)
                data.append(None)
                data.append(None)
                data.append(None)
                data.append(None)
                data.append(None)
                data.append(None)
                data.append(None)
                data.append(None)
                data.append(None)
            if vuln.get('cve').get('weaknesses') is not None:
                data.append(vuln.get('cve').get('weaknesses')[0].get('description')[0].get('value'))
            else:
                data.append(None)
            data = [str(item).encode('utf-8').decode('utf-8') if item is not None else '' for item in data]
            writer.writerow(data)

if __name__ == "__main__":
    # start_date = "2024-01-01T00:00:00.000"
    # end_date = "2024-01-02T00:00:00.000"
    # nvd_data = get_nvd_data_from_date(start_date, end_date).get('vulnerabilities')

    nvd_data = []
    cnnvd_file_name = "./data/data_with_type_202401.csv"
    id_list = read_id_from_cnnvd(cnnvd_file_name)
    id_list = ["CVE-2023-51337","CVE-2023-51328","CVE-2023-51303","CVE-2023-51325","CVE-2023-51306"]
    
    count = 0
    for id in id_list:
        res = get_nvd_data_from_id(id)
        if res:
            nvd_data += res.get('vulnerabilities')
        else:
            nvd_data += [None]
        count += 1
        print(count)

    if nvd_data:
        target_file = "./data/nvd_data_from_id.csv"
        data_processing(nvd_data, target_file)
    else:
        print("No data retrieved from NVD.")
    