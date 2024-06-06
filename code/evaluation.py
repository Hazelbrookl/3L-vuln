import csv
from .lllchat import cvss_metrics_description_prompt_generate, vulnerability_severity_evaluation_prompt_generate, dataset_keyword_extract_prompt_generate, dataset_metric_hint_extract_prompt_generate, translate_prompt_generate, evaluation_format_prompt_generate, call_llm
import seaborn as sns
import matplotlib.pyplot as plt
import pandas as pd
plt.rcParams['font.sans-serif'] = ['SimHei']
from sklearn.metrics import accuracy_score, recall_score, precision_score, f1_score, confusion_matrix
import re
import random
import math
import concurrent.futures

CVSS_AV_NETWORK = 0.85
CVSS_AV_ADJACENT_NETWORK = 0.62
CVSS_AV_LOCAL = 0.55
CVSS_AV_PHYSICAL = 0.2

CVSS_AC_LOW = 0.77
CVSS_AC_HIGH = 0.44

CVSS_PR_NONE = 0.85
CVSS_PR_LOW_CHANGED = 0.68
CVSS_PR_HIGH_CHANGED = 0.50
CVSS_PR_LOW_UNCHANGED = 0.62
CVSS_PR_HIGH_UNCHANGED = 0.27

CVSS_UI_NONE = 0.85
CVSS_UI_REQUIRED = 0.62

metric_names = ["攻击向量(Attack Vector, AV)", "攻击复杂度(Attack Complexity, AC)", "权限要求(Privileges Required, PR)", "用户交互(User Interaction,UI)", 
           "作用域(Scope, S)", "机密性影响(Confidentiality Impact, C)", "完整性影响(Integrity Impact, I)", "可用性影响(Availability Impact, A)"]

def get_metrics():

    metrics = []
    with open('./data/cvss_metrics.csv', 'r', newline='', encoding='utf-8') as csvfile:
# 使用 csv.reader 读取 CSV 文件内容
        reader = csv.reader(csvfile)

        for row in reader:
            metrics.append(row)
    return metrics

def description_generate(metric_names):
    for metric_name in metric_names:
        prompt = cvss_metrics_description_prompt_generate(metric_name)
        ans = call_llm(prompt)
        print(ans)

def evaluation_test(metrics):

    metric_index = 3

    input_list = []
    type_list = []
    with open('./data/data_with_type_202401.csv', 'r', newline='', encoding='utf-8') as csvfile:
    # 使用 csv.reader 读取 CSV 文件内容
        reader = csv.reader(csvfile)
        next(reader)

        for row in reader:
            type_list.append(row[6])

    data_type_list = []
    with open('./data/data_with_type_202402.csv', 'r', newline='', encoding='utf-8') as csvfile:
    # 使用 csv.reader 读取 CSV 文件内容
        reader = csv.reader(csvfile)
        next(reader)

        for row in reader:
            data_type_list.append(row[6])

    severity_true = []
    with open('./data/nvd_data_from_id_202401.csv', 'r', newline='', encoding='utf-8') as csvfile:
    # 使用 csv.reader 读取 CSV 文件内容
        reader = csv.reader(csvfile)
        next(reader)

        for row in reader:
            input_list.append(row[4])
            severity_true.append(row[5:9])

    hint_list = []
    with open('./data/hint_ui_202402.csv', 'r', newline='', encoding='utf-8') as csvfile:
    # 使用 csv.reader 读取 CSV 文件内容
        reader = csv.reader(csvfile)

        for row in reader:
            hint_list.append(row[0])

    severity_pred = []

    for index, description in enumerate(input_list):
        
        input_type = type_list[index]
        index_dict = {key:[] for key in metrics[metric_index][1:]}
        index_count = 0
        for i, type in enumerate(data_type_list):
            if type == input_type and severity_true[i][metric_index] != "":
                index_dict.get(severity_true[i][metric_index]).append(i)
                index_count += 1

        examples_total = 10
        examples = {key:[] for key in metrics[metric_index][1:]}
        for key, value in index_dict.items():
            if index_count == 0:
                break
            for i in range(math.ceil((len(value)/index_count)*examples_total)):
                if value:  # 确保列表不是空
                    choice = random.choice(value)
                    while severity_true[choice][metric_index] == "":
                        value.remove(choice)
                        if value:
                            choice = random.choice(value)
                        else:
                            choice = None
                            break
                    if choice:
                        examples.get(key).append(hint_list[choice])
                else:
                    break

        for key, value in examples.items():
            if len(value) == 0:
                value = "库中暂无该取值的数据。"

        ans = []
        prompt = vulnerability_severity_evaluation_prompt_generate(description, metric_names[metric_index], metrics[metric_index][0], metrics[metric_index][1:],examples)
        res = call_llm(prompt)
        prompt = evaluation_format_prompt_generate(res, metric_names[metric_index], metrics[metric_index][1:])
        ans.append(call_llm(prompt))
        ans.append(severity_true[index][metric_index])
        severity_pred.append(ans)

    with open('./data/evaluation_ui_test_202401.csv', 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)

        for pred in severity_pred:
            writer.writerow(pred)

def compute_confuse_matrix():
    severity_pred = []
    severity_true = []

    av_pred = []
    av_true = []
    ac_pred = []
    ac_true = []
    pr_pred = []
    pr_true = []
    ui_pred = []
    ui_true = []

    with open('./data/evaluation_ui_test_202401.csv', 'r', newline='', encoding='utf-8') as csvfile:
    # 使用 csv.reader 读取 CSV 文件内容
        reader = csv.reader(csvfile)

        for row in reader:
            severity_pred.append([row[0]])
            severity_true.append([row[1]])

    for preds, trues in zip(severity_pred, severity_true):
        invalid = False
        for true in trues:
            if true == "":
                invalid = True
                break
        if invalid:
            continue

        av_pred.append(preds[0])
        av_true.append(trues[0])
        # ac_pred.append(preds[1])
        # ac_true.append(trues[1])
        # pr_pred.append(preds[2])
        # pr_true.append(trues[2])
        # ui_pred.append(preds[3])
        # ui_true.append(trues[3])

    labels_av = sorted(list(set(av_pred)))
    print(labels_av)
    labels_av = sorted(list(set(av_true)))
    labels_ac = sorted(list(set(ac_true)))
    labels_pr = sorted(list(set(pr_true)))
    labels_ui = sorted(list(set(ui_true)))
    
    # 计算混淆矩阵
    cm = confusion_matrix(av_true, av_pred)

    # 计算准确率
    accuracy = accuracy_score(av_true, av_pred)

    # 计算召回率
    recall = recall_score(av_true, av_pred, average='weighted', zero_division=0)

    # 计算精确率
    precision = precision_score(av_true, av_pred, average='weighted', zero_division=0)

    # 计算 F1 分数
    f1 = f1_score(av_true, av_pred, average='weighted')

    print("accuracy：" + str(accuracy))
    print("recall：" + str(recall))
    print("precision：" + str(precision))
    print("f1：" + str(f1))
    # 绘制热力图
    plt.figure(figsize=(8, 8))
    sns.heatmap(cm, annot=True, cmap='Blues', fmt='g', xticklabels=labels_av, yticklabels=labels_av)
    plt.xlabel('Predicted labels')
    plt.ylabel('True labels')
    plt.title('Confusion Matrix')
    plt.show()

    # # 计算混淆矩阵
    # cm = confusion_matrix(ac_true, ac_pred)

    # # 计算准确率
    # accuracy = accuracy_score(ac_true, ac_pred)

    # # 计算召回率
    # recall = recall_score(ac_true, ac_pred, average='weighted', zero_division=0)

    # # 计算精确率
    # precision = precision_score(ac_true, ac_pred, average='weighted', zero_division=0)

    # # 计算 F1 分数
    # f1 = f1_score(ac_true, ac_pred, average='weighted')

    # print("accuracy：" + str(accuracy))
    # print("recall：" + str(recall))
    # print("precision：" + str(precision))
    # print("f1：" + str(f1))
    # # 绘制热力图
    # plt.figure(figsize=(8, 8))
    # sns.heatmap(cm, annot=True, cmap='Blues', fmt='g', xticklabels=labels_ac, yticklabels=labels_ac)
    # plt.xlabel('Predicted labels')
    # plt.ylabel('True labels')
    # plt.title('Confusion Matrix')
    # plt.show()

    # # 计算混淆矩阵
    # cm = confusion_matrix(pr_true, pr_pred)

    # # 计算准确率
    # accuracy = accuracy_score(pr_true, pr_pred)

    # # 计算召回率
    # recall = recall_score(pr_true, pr_pred, average='weighted', zero_division=0)

    # # 计算精确率
    # precision = precision_score(pr_true, pr_pred, average='weighted', zero_division=0)

    # # 计算 F1 分数
    # f1 = f1_score(pr_true, pr_pred, average='weighted')

    # print("accuracy：" + str(accuracy))
    # print("recall：" + str(recall))
    # print("precision：" + str(precision))
    # print("f1：" + str(f1))
    # # 绘制热力图
    # plt.figure(figsize=(8, 8))
    # sns.heatmap(cm, annot=True, cmap='Blues', fmt='g', xticklabels=labels_pr, yticklabels=labels_pr)
    # plt.xlabel('Predicted labels')
    # plt.ylabel('True labels')
    # plt.title('Confusion Matrix')
    # plt.show()

    # # 计算混淆矩阵
    # cm = confusion_matrix(ui_true, ui_pred)

    # # 计算准确率
    # accuracy = accuracy_score(ui_true, ui_pred)

    # # 计算召回率
    # recall = recall_score(ui_true, ui_pred, average='weighted', zero_division=0)

    # # 计算精确率
    # precision = precision_score(ui_true, ui_pred, average='weighted', zero_division=0)

    # # 计算 F1 分数
    # f1 = f1_score(ui_true, ui_pred, average='weighted')

    # print("accuracy：" + str(accuracy))
    # print("recall：" + str(recall))
    # print("precision：" + str(precision))
    # print("f1：" + str(f1))
    # # 绘制热力图
    # plt.figure(figsize=(8, 8))
    # sns.heatmap(cm, annot=True, cmap='Blues', fmt='g', xticklabels=labels_ui, yticklabels=labels_ui)
    # plt.xlabel('Predicted labels')
    # plt.ylabel('True labels')
    # plt.title('Confusion Matrix')
    # plt.show()

def compute_exploitability_score():
    av_pred = []
    with open('./data/evaluation_av_202401.csv', 'r', newline='', encoding='utf-8') as csvfile:
    # 使用 csv.reader 读取 CSV 文件内容
        reader = csv.reader(csvfile)

        for row in reader:
            av_pred.append(row[0])
    ac_pred = []
    with open('./data/evaluation_ac_test_202401.csv', 'r', newline='', encoding='utf-8') as csvfile:
    # 使用 csv.reader 读取 CSV 文件内容
        reader = csv.reader(csvfile)

        for row in reader:
            ac_pred.append(row[0])
    pr_pred = []
    with open('./data/evaluation_pr_202401.csv', 'r', newline='', encoding='utf-8') as csvfile:
    # 使用 csv.reader 读取 CSV 文件内容
        reader = csv.reader(csvfile)

        for row in reader:
            pr_pred.append(row[0])
    ui_pred = []
    with open('./data/evaluation_ui_test_202401.csv', 'r', newline='', encoding='utf-8') as csvfile:
    # 使用 csv.reader 读取 CSV 文件内容
        reader = csv.reader(csvfile)

        for row in reader:
            ui_pred.append(row[0])
    s_true = []
    exploitability_true = []
    with open('./data/nvd_data_from_id_202401.csv', 'r', newline='', encoding='utf-8') as csvfile:
    # 使用 csv.reader 读取 CSV 文件内容
        reader = csv.reader(csvfile)
        next(reader)

        for row in reader:
            s_true.append(row[9])
            exploitability_true.append(row[13])
    
    exploitability_pred = []
    for i in range(len(exploitability_true)):
        if exploitability_true[i] == "":
            exploitability_pred.append("")
            continue
        score = 8.22
        if av_pred[i] == "NETWORK":
            score *= CVSS_AV_NETWORK
        elif av_pred[i] == "ADJACENT_NETWORK":
            score *= CVSS_AV_ADJACENT_NETWORK
        elif av_pred[i] == "LOCAL":
            score *= CVSS_AV_LOCAL
        elif av_pred[i] == "PHYSICAL":
            score *= CVSS_AV_PHYSICAL
        if ac_pred[i] == "LOW":
            score *= CVSS_AC_LOW
        elif ac_pred[i] == "HIGH":
            score *= CVSS_AC_HIGH
        if pr_pred[i] == "NONE":
            score *= CVSS_PR_NONE
        elif pr_pred[i] == "LOW":
            if s_true[i] == "CHANGED":
                score *= CVSS_PR_LOW_CHANGED
            elif s_true[i] == "UNCHANGED":
                score *= CVSS_PR_LOW_UNCHANGED
        elif pr_pred[i] == "HIGH":
            if s_true[i] == "CHANGED":
                score *= CVSS_PR_HIGH_CHANGED
            elif s_true[i] == "UNCHANGED":
                score *= CVSS_PR_HIGH_UNCHANGED
        if ui_pred[i] == "NONE":
            score *= CVSS_UI_NONE
        elif ui_pred[i] == "REQUIRED":
            score *= CVSS_UI_REQUIRED
        exploitability_pred.append(score)

    exploitability_default = []
    for i in range(len(exploitability_true)):
        if exploitability_true[i] == "":
            exploitability_default.append("")
            continue
        score = 8.22
        if av_pred[i] == "NETWORK":
            score *= CVSS_AV_NETWORK
        elif av_pred[i] == "ADJACENT_NETWORK":
            score *= CVSS_AV_ADJACENT_NETWORK
        elif av_pred[i] == "LOCAL":
            score *= CVSS_AV_LOCAL
        elif av_pred[i] == "PHYSICAL":
            score *= CVSS_AV_PHYSICAL
        if ac_pred[i] == "LOW":
            score *= CVSS_AC_LOW
        elif ac_pred[i] == "HIGH":
            score *= CVSS_AC_HIGH
        score *= CVSS_PR_NONE
        if ui_pred[i] == "NONE":
            score *= CVSS_UI_NONE
        elif ui_pred[i] == "REQUIRED":
            score *= CVSS_UI_REQUIRED
        exploitability_default.append(score)

    # with open('./data/evaluation_exploitability_202401.csv', 'w', newline='', encoding='utf-8') as csvfile:
    #     writer = csv.writer(csvfile)

    #     for pred, default, true in zip(exploitability_pred, exploitability_default, exploitability_true):
    #         writer.writerow([pred, default, true])

    mse = 0
    valid_count = 0
    greater_count = 0
    smaller_count = 0
    errors = []
    for pred, true in zip(exploitability_pred, exploitability_true):
        if pred != "" and true != "":
            mse += pow((pred - float(true)), 2)
            valid_count += 1
            if pred >= float(true):
                greater_count += 1
            else:
                smaller_count += 1
            errors.append(abs(pred - float(true)))
    mse /= valid_count
    print("有效数据：" + str(valid_count))
    print("均方误差：" + str(mse))
    print("结果较高：" + str(greater_count))
    print("结果较低：" + str(smaller_count))

    bins = [0.05, 0.5, 1.0, 1.5]
    counts = [sum(e <= bin for e in errors) for bin in bins]
    print(counts)

    sns.set(font_scale=2.5)
    plt.rc('font', family='Times New Roman')

    # 创建条形图
    plt.figure(figsize=(10, 8))
    plt.bar([str(bin) for bin in bins], counts, color='skyblue')
    plt.xlabel('loss')
    plt.ylabel('n@loss')
    # plt.title('不同误差范围内的条数')
    plt.show()

    mse = 0
    valid_count = 0
    greater_count = 0
    smaller_count = 0
    errors = []
    for default, true in zip(exploitability_default, exploitability_true):
        if default != "" and true != "":
            mse += pow((default - float(true)), 2)
            valid_count += 1
            if default >= float(true):
                greater_count += 1
            else:
                smaller_count += 1
            errors.append(abs(default - float(true)))
    mse /= valid_count
    print("有效数据：" + str(valid_count))
    print("均方误差：" + str(mse))
    print("结果较高：" + str(greater_count))
    print("结果较低：" + str(smaller_count))

    bins = [0.05, 0.5, 1.0, 1.5]
    counts = [sum(e <= bin for e in errors) for bin in bins]
    print(counts)

    sns.set(font_scale=2.5)
    plt.rc('font', family='Times New Roman')

    # 创建条形图
    plt.figure(figsize=(10, 8))
    plt.bar([str(bin) for bin in bins], counts, color='skyblue')
    plt.xlabel('loss')
    plt.ylabel('n@loss')
    # plt.title('不同误差范围内的条数')
    plt.show()
    
def extract_dataset_keyword(metrics):

    data_list = []
    with open('./data/nvd_data_from_id_202402.csv', 'r', newline='', encoding='utf-8') as csvfile:
    # 使用 csv.reader 读取 CSV 文件内容
        reader = csv.reader(csvfile)
        next(reader)

        for row in reader:
            data_list.append(row[4:9])

    keywords = []
        
    for index, data in enumerate(data_list):
        prompt = dataset_keyword_extract_prompt_generate(data[0], metric_names[0], metrics[0][1:], data[1], metrics[0][0])
        ans = call_llm(prompt).split('$')
        keywords.append(ans)

        if index >= 10:
            break

    with open('./data/keyword_202402.csv', 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)

        for keyword in keywords:
            writer.writerow(keyword)

def extract_dataset_hint(metrics):
    data_list = []
    with open('./data/nvd_data_from_id_202402.csv', 'r', newline='', encoding='utf-8') as csvfile:
    # 使用 csv.reader 读取 CSV 文件内容
        reader = csv.reader(csvfile)
        next(reader)

        for row in reader:
            data_list.append(row[4:9])

    hints = []
        
    for index, data in enumerate(data_list):
        prompt = translate_prompt_generate(data[0])
        info = call_llm(prompt)
        prompt = dataset_metric_hint_extract_prompt_generate(info, metric_names[3], metrics[3][1:], data[4], metrics[3][0])
        ans = call_llm(prompt)
        hints.append(ans)

    with open('./data/hint_ui_202402.csv', 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)

        for hint in hints:
            writer.writerow([hint])

def statistics():
    
    type_list = []
    with open('./data/data_with_type_202402.csv', 'r', newline='', encoding='utf-8') as csvfile:
    # 使用 csv.reader 读取 CSV 文件内容
        reader = csv.reader(csvfile)
        next(reader)

        for row in reader:
            type_list.append(row[6])

    metric_list = []
    with open('./data/nvd_data_from_id_202402.csv', 'r', newline='', encoding='utf-8') as csvfile:
    # 使用 csv.reader 读取 CSV 文件内容
        reader = csv.reader(csvfile)
        next(reader)

        for row in reader:
            metric_list.append(row[5:9])

    type_valid = []
    metric_valid = []

    for type, metrics in zip(type_list, metric_list):
        invalid = False
        for metric in metrics:
            if metric == "":
                invalid = True
                break
        if invalid:
            continue
        type_valid.append(type)
        metric_valid.append(metrics[3])

    cross_table = pd.crosstab(type_valid, metric_valid)

    plt.figure(figsize=(8, 8))
    sns.heatmap(cross_table, annot=True, cmap='YlGnBu', fmt='d')
    plt.xlabel('Predicted labels')
    plt.ylabel('True labels')
    plt.title('Confusion Matrix')
    plt.show()

def evaluate_single_metric(metric_index, data_type_list, input_type, severity_true, hints, description, metric_names, metrics):
    index_dict = {key: [] for key in metrics[metric_index][1:]}
    index_count = 0
    for i, type in enumerate(data_type_list):
        if type == input_type and severity_true[i][metric_index] != "":
            index_dict.get(severity_true[i][metric_index]).append(i)
            index_count += 1

    examples_total = 10
    examples = {key: [] for key in metrics[metric_index][1:]}
    for key, value in index_dict.items():
        if index_count == 0:
            break
        for i in range(math.ceil((len(value) / index_count) * examples_total)):
            if value:  # 确保列表不是空
                choice = random.choice(value)
                while severity_true[choice][metric_index] == "":
                    value.remove(choice)
                    if value:
                        choice = random.choice(value)
                    else:
                        choice = None
                        break
                if choice:
                    examples.get(key).append(hints[metric_index][choice])
            else:
                break

    for key, value in examples.items():
        if len(value) == 0:
            value = "库中暂无该取值的数据。"

    prompt = vulnerability_severity_evaluation_prompt_generate(
        description, metric_names[metric_index], metrics[metric_index][0], metrics[metric_index][1:], examples)
    res = call_llm(prompt)
    prompt = evaluation_format_prompt_generate(res, metric_names[metric_index], metrics[metric_index][1:])
    ans = call_llm(prompt)

    ans = ans.upper()
    res = "无法判断"
    for key in metrics[metric_index][1:]:
        if re.search(key, ans):
            res = key
    return metric_index, res

def api_evaluation(description, input_type):

    metrics = get_metrics()
    
    data_type_list = []
    with open('./data/data_with_type_202402.csv', 'r', newline='', encoding='utf-8') as csvfile:
    # 使用 csv.reader 读取 CSV 文件内容
        reader = csv.reader(csvfile)
        next(reader)

        for row in reader:
            data_type_list.append(row[6])

    severity_true = []
    with open('./data/nvd_data_from_id_202402.csv', 'r', newline='', encoding='utf-8') as csvfile:
    # 使用 csv.reader 读取 CSV 文件内容
        reader = csv.reader(csvfile)
        next(reader)

        for row in reader:
            severity_true.append(row[5:9])

    hint_av_list = []
    with open('./data/hint_av_202402.csv', 'r', newline='', encoding='utf-8') as csvfile:
    # 使用 csv.reader 读取 CSV 文件内容
        reader = csv.reader(csvfile)

        for row in reader:
            hint_av_list.append(row[0])

    hint_ac_list = []
    with open('./data/hint_ac_202402.csv', 'r', newline='', encoding='utf-8') as csvfile:
    # 使用 csv.reader 读取 CSV 文件内容
        reader = csv.reader(csvfile)

        for row in reader:
            hint_ac_list.append(row[0])

    hint_pr_list = []
    with open('./data/nvd_data_from_id_202402.csv', 'r', newline='', encoding='utf-8') as csvfile:
    # 使用 csv.reader 读取 CSV 文件内容
        reader = csv.reader(csvfile)
        next(reader)

        for row in reader:
            hint_pr_list.append(row[4])

    hint_ui_list = []
    with open('./data/hint_ui_202402.csv', 'r', newline='', encoding='utf-8') as csvfile:
    # 使用 csv.reader 读取 CSV 文件内容
        reader = csv.reader(csvfile)

        for row in reader:
            hint_ui_list.append(row[0])

    hints = [hint_av_list, hint_ac_list, hint_pr_list, hint_ui_list]

    severity = [None] * 4

    # for metric_index in range(4):
    #     index_dict = {key:[] for key in metrics[metric_index][1:]}
    #     index_count = 0
    #     for i, type in enumerate(data_type_list):
    #         if type == input_type and severity_true[i][metric_index] != "":
    #             index_dict.get(severity_true[i][metric_index]).append(i)
    #             index_count += 1

    #     examples_total = 10
    #     examples = {key:[] for key in metrics[metric_index][1:]}
    #     for key, value in index_dict.items():
    #         if index_count == 0:
    #             break
    #         for i in range(math.ceil((len(value)/index_count)*examples_total)):
    #             if value:  # 确保列表不是空
    #                 choice = random.choice(value)
    #                 while severity_true[choice][metric_index] == "":
    #                     value.remove(choice)
    #                     if value:
    #                         choice = random.choice(value)
    #                     else:
    #                         choice = None
    #                         break
    #                 if choice:
    #                     examples.get(key).append(hints[metric_index][choice])
    #             else:
    #                 break

    #     for key, value in examples.items():
    #         if len(value) == 0:
    #             value = "库中暂无该取值的数据。"

    #     prompt = vulnerability_severity_evaluation_prompt_generate(description, metric_names[metric_index], metrics[metric_index][0], metrics[metric_index][1:],examples)
    #     res = call_llm(prompt)
    #     prompt = evaluation_format_prompt_generate(res, metric_names[metric_index], metrics[metric_index][1:])
    #     ans = call_llm(prompt)

    #     ans = ans.upper()
    #     res = "无法判断"
    #     for key in metrics[metric_index][1:]:
    #         if re.search(key, ans):
    #             res = key
    #     severity.append(res)
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        future_to_index = {executor.submit(evaluate_single_metric, metric_index, data_type_list, input_type, severity_true, hints, description, metric_names, metrics): metric_index for metric_index in range(4)}
    
    for future in concurrent.futures.as_completed(future_to_index):
        index, result = future.result()
        severity[index] = result
    
    return severity  

if __name__ == "__main__":
    # description_generate(metric_names)
    metrics = get_metrics()
    # statistics()
    # extract_dataset_keyword(metrics)
    # extract_dataset_hint(metrics)
    # evaluation_test(metrics)
    # compute_confuse_matrix()
    compute_exploitability_score()
