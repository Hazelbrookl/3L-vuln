# import os
# os.environ["DASHSCOPE_API_KEY"] = "sk-e3ca2fab4b3541b7b3fc268902293edd"

# from langchain.llms import tongyi
# from langchain.prompts import (
#     PromptTemplate,
# )
# from langchain.chains import LLMChain

# import csv

# keys = ['severity','pred-severity']

# template = """
#            Description: 以下是一个漏洞报告的信息，包含（漏洞名、漏洞id、发布日期、修改日期、漏洞类型、漏洞描述）等：{question}
#            Answer: 请关注漏洞类型、漏洞描述等信息，推断该漏洞的危害等级，可以选择的答案有（低危、中危、高危、超危）这四个等级，请仅回答你选择的等级，共两个汉字，不要回答其他内容。
#            """

# prompt = PromptTemplate(
#     template=template,
#     input_variables=["question"])

# llm = tongyi.Tongyi()

# llm_chain = LLMChain(prompt=prompt, llm=llm)

# pred_answer = []

# # 打开 CSV 文件进行读取
# with open('./data/data_test.csv', 'r', newline='', encoding='utf-8') as csvfile:
#     # 使用 csv.reader 读取 CSV 文件内容
#     reader = csv.reader(csvfile)
#     next(reader)

#     count = 0
#     count_incorrect = 0
#     # 遍历 CSV 文件的每一行数据
#     for row in reader:
#         # 在这里处理每一行数据
#         question = f"""
#         name：{row[0]}；
#         vuln-id：{row[1]}；
#         published：{row[2]}；
#         modified：{row[3]}；
#         vuln-type：{row[6]}；
#         vuln-descript：{row[7]}；
#         """
        
#         res = llm_chain.run(question)

#         pred_answer.append([row[5], res])
#         if res != row[5]:
#              count_incorrect += 1

#         count += 1
#         print(count)
#         if count >= 100:
#             break

# with open('./data/pred_severity_test.csv', 'w', newline='', encoding='utf-8') as csvfile:
#         writer = csv.writer(csvfile)
        
#         # 写入CSV头部
#         writer.writerow(keys)
        
#         # 遍历XML元素并写入CSV
#         for ans in pred_answer:
#             writer.writerow(ans)
#         writer.writerow([count_incorrect])

import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np

# # 假设你有以下的混淆矩阵数据
# TP = 266  # True Positive
# FN = 250   # False Negative
# FP = 20  # False Positive
# TN = 386  # True Negative

# # 创建一个混淆矩阵
# confusion_matrix = np.array([[TP, FN], [FP, TN]])

# confusion_matrix = np.array([
#     [62, 22, 2],  # A
#     [138, 95, 10],   # B
#     [240, 149, 39],   # C
# ])

confusion_matrix = np.array([
    [10, 0, 15, 0],  # A
    [3, 76, 37, 0],   # B
    [1, 13, 599, 0],   # C
    [0, 0, 1, 2]    # D
])

sns.set(font_scale=6)
plt.rc('font', family='Times New Roman')

# 绘制混淆矩阵图
plt.figure(figsize=(10, 10))
sns.heatmap(confusion_matrix, annot=True, fmt='d', cmap='Blues', cbar=False, annot_kws={"size": 72},
            xticklabels=['A', 'L', 'N', 'P'], 
            yticklabels=['A', 'L', 'N', 'P'])

# 添加标题和标签
# plt.title('Confusion Matrix')
# plt.xlabel('Pred')
# plt.ylabel('True')

# 显示图表
plt.show()


