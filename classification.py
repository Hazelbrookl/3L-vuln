import csv
from .lllchat import vulnerability_type_classification_zero_shot_prompt_generate, vulnerability_type_classification_one_shot_prompt_generate, vulnerability_type_classification_CoT_prompt_generate, call_llm
import seaborn as sns
import matplotlib.pyplot as plt
plt.rcParams['font.sans-serif'] = ['SimHei']
from sklearn.metrics import accuracy_score, recall_score, precision_score, f1_score, confusion_matrix
import re
import numpy as np

def get_labels():

    labels = []
    with open('./data/severity_vuln_type_202402.csv', 'r', newline='', encoding='utf-8') as csvfile:
# 使用 csv.reader 读取 CSV 文件内容
        reader = csv.reader(csvfile)

        for row in reader:
            labels = row[1:]
            break
    return labels

def vuln_classification(labels):

    input_list = []
    type_true = []
    with open('./data/data_with_type_202401.csv', 'r', newline='', encoding='utf-8') as csvfile:
    # 使用 csv.reader 读取 CSV 文件内容
        reader = csv.reader(csvfile)
        next(reader)

        for row in reader:
            input_list.append(row[7])
            type_true.append(row[6])

    type_pred = []
    
    for index, description in enumerate(input_list):
        prompt = vulnerability_type_classification_zero_shot_prompt_generate(description, labels)
        ans = call_llm(prompt)

        type_pred.append(ans)

    with open('./data/classification_202401.csv', 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)

        for pred, true in zip(type_pred, type_true):
            writer.writerow([pred, true])

def check_if_contain():
    input_list = []
    type_true = []
    with open('./data/data_with_type_202402.csv', 'r', newline='', encoding='utf-8') as csvfile:
    # 使用 csv.reader 读取 CSV 文件内容
        reader = csv.reader(csvfile)
        next(reader)

        for row in reader:
            input_list.append(row[7])
            type_true.append(row[6])

    contain_count = 0

    for index, description in enumerate(input_list):
        match = re.search(type_true[index], description)
        if match:
            contain_count += 1
    
    print(contain_count)

def compute_confuse_matrix(labels):
    # 示例预测结果和真实标签
    type_pred = []
    type_true = []

    type_pred_valid = []
    type_true_valid = []

    with open('./data/classification_202401.csv', 'r', newline='', encoding='utf-8') as csvfile:
    # 使用 csv.reader 读取 CSV 文件内容
        reader = csv.reader(csvfile)

        for row in reader:
            type_pred.append(row[0])
            type_true.append(row[1])

    labels_dict = {}
    for index, label in enumerate(labels):
        labels_dict[label] = index

    invalid_count = 0
    correct_count = 0

    for pred, true in zip(type_pred, type_true):
        index_pred = labels_dict.get(pred)
        if index_pred is None:
            invalid_count += 1
            continue
        type_pred_valid.append(pred)
        type_true_valid.append(true)
        index_true = labels_dict.get(true)
        if index_pred == index_true:
            correct_count += 1

    # 计算混淆矩阵
    cm = confusion_matrix(type_true_valid, type_pred_valid)

    # 计算准确率
    accuracy = accuracy_score(type_true_valid, type_pred_valid)

    # 计算召回率
    recall = recall_score(type_true_valid, type_pred_valid, average='weighted')

    # 计算精确率
    precision = precision_score(type_true_valid, type_pred_valid, average='weighted')

    # 计算 F1 分数
    f1 = f1_score(type_true_valid, type_pred_valid, average='weighted')

    print("无效标签数：" + str(invalid_count))
    print("预测正确数：" + str(correct_count))
    print("accuracy：" + str(accuracy))
    print("recall：" + str(recall))
    print("precision：" + str(precision))
    print("f1：" + str(f1))
    # 绘制热力图
    annot = np.where(cm != 0, cm, '')
    # sns.set(font_scale=3)
    # plt.rc('font', family='Times New Roman')
    plt.figure(figsize=(10, 10))
    sns.heatmap(cm, annot=annot, cmap='Blues', fmt='', xticklabels=labels, yticklabels=labels, cbar=False, annot_kws={"size": 18})
    plt.xlabel('Predicted labels')
    plt.ylabel('True labels')
    # plt.title('Confusion Matrix')
    plt.show()

def api_classification(description):
    labels = get_labels()
    prompt = vulnerability_type_classification_zero_shot_prompt_generate(description, labels)
    ans = call_llm(prompt)

    res = "无法判断"
    for label in labels:
        if re.search(label, ans):
            res = label

    return res

if __name__ == "__main__":
    labels = get_labels()
    # vuln_classification(labels)
    compute_confuse_matrix(labels)
    # check_if_contain()