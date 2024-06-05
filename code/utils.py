import xml.etree.ElementTree as ET
import csv
from collections import Counter
import pandas as pd

keys = ['name', 'vuln-id', 'published', 'modified', 'source', 'severity', 'vuln-type', 'vuln-descript', 'cve-id', 'vuln-solution']

data_list = []

def xml2csv():
    tree = ET.parse('./data/202401.xml')
    root = tree.getroot()
    
    # 打开CSV文件进行写入
    with open('./data/data_with_type_test.csv', 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        
        # 写入CSV头部
        writer.writerow(keys)
        
        # 遍历XML元素并写入CSV
        for element in root.findall('entry'):
            if element.find('vuln-type').text != '其他':
                data = [
                    element.find('name').text,
                    element.find('vuln-id').text,
                    element.find('published').text,
                    element.find('modified').text,
                    element.find('source').text,
                    element.find('severity').text,
                    element.find('vuln-type').text,
                    element.find('vuln-descript').text,
                    element.find('other-id').find('cve-id').text,
                    element.find('vuln-solution').text,
                ]
                data = [item.encode('utf-8').decode('utf-8') if item is not None else '' for item in data]
                writer.writerow(data)

                data_dict = {key: value for key, value in zip(keys, data)}
                data_list.append(data_dict)

def count_severity_vuln_type(data_list):
    df = pd.DataFrame(data_list)

    # 使用pivot_table进行透视表操作
    pivot_table = df.pivot_table(index='severity', columns='vuln-type', aggfunc='size', fill_value=0)

    # 打印生成的透视表
    print(pivot_table)

    # 将透视表存储为CSV文件
    pivot_table.to_csv('./data/severity_vuln_type_202401.csv')
    severity_counter = Counter(item['severity'] for item in data_list)
    vuln_type_counter = Counter(item['vuln-type'] for item in data_list)

    print("Severity 统计:")
    print(severity_counter)

    print("\nVuln-type 统计:")
    print(vuln_type_counter)

if __name__ == "__main__":
    xml2csv()
    count_severity_vuln_type(data_list)
    