import csv
import random
from .lllchat import check_duplicated_report_prompt_generate, report_detail_hint_prompt_generate, check_duplicated_report_with_hint_prompt_generate, call_llm
from .similarity import extract_input_entity, find_similar


keys = ['is_duplicated', 'correct_match', 'details']

def check_duplicated():

    input_list = []
    with open('./data/data_with_type_202401.csv', 'r', newline='', encoding='utf-8') as csvfile:
    # 使用 csv.reader 读取 CSV 文件内容
        reader = csv.reader(csvfile)
        next(reader)

        for row in reader:
            input_list.append(row[7])

    data_list = []
    with open('./data/nvd_data_from_id_202402.csv', 'r', newline='', encoding='utf-8') as csvfile:
    # 使用 csv.reader 读取 CSV 文件内容
        reader = csv.reader(csvfile)
        next(reader)

        for row in reader:
            data_list.append(row[4])

    index_list = []
    with open('./data/similar_202401.csv', 'r', newline='', encoding='utf-8') as csvfile:
    # 使用 csv.reader 读取 CSV 文件内容
        reader = csv.reader(csvfile)

        for row in reader:
            index_list.append(row)
    index_list = index_list[:-2]

    print(len(input_list))
    print(len(data_list))
    print(len(index_list))

    duplicated_list = []

    duplicated_count = 0
    match_count = 0

    for index, similar_indices in enumerate(index_list):
        print(index)
        is_duplicated = False
        correct_match = False
        duplicated_content = []
        for similar_index in similar_indices:
            similar_index = int(similar_index)

            # prompt = check_duplicated_report_prompt_generate(input_list[index], data_list[similar_index])
            # ans = call_llm(prompt)
            prompt = report_detail_hint_prompt_generate(input_list[index], data_list[similar_index])
            ans = call_llm(prompt)
            prompt = check_duplicated_report_with_hint_prompt_generate(input_list[index], data_list[similar_index], ans)
            ans = call_llm(prompt)
      
            if ans == "是":
                is_duplicated = True
                if index == similar_index:
                    correct_match = True
            duplicated_content.append(similar_index)
            duplicated_content.append(ans)
        if correct_match:
            match_count += 1
        if is_duplicated:
            duplicated_count += 1
        duplicated_content.insert(0, correct_match)
        duplicated_content.insert(0, is_duplicated)
        duplicated_list.append(duplicated_content)

    with open('./data/hint_duplicated_202401.csv', 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)

        writer.writerow(keys)
        
        for duplicated_content in duplicated_list:
            writer.writerow(duplicated_content)

        writer.writerow(["重复报告识别总数", duplicated_count])
        writer.writerow(["重复条目对应正确", match_count])  

def check_matched_items():
    input_list = []
    with open('./data/data_with_type_202402.csv', 'r', newline='', encoding='utf-8') as csvfile:
    # 使用 csv.reader 读取 CSV 文件内容
        reader = csv.reader(csvfile)
        next(reader)

        for row in reader:
            input_list.append(row[7])

    data_list = []
    with open('./data/nvd_data_from_id_202402.csv', 'r', newline='', encoding='utf-8') as csvfile:
    # 使用 csv.reader 读取 CSV 文件内容
        reader = csv.reader(csvfile)
        next(reader)

        for row in reader:
            data_list.append(row[4])

    duplicated_count = 0
    duplicated_list = []
    for index, (info_1, info_2) in enumerate(zip(input_list, data_list)):
        is_duplicated = False
        prompt = check_duplicated_report_prompt_generate(info_1, info_2)
        ans = call_llm(prompt)
        if ans == "是":
                is_duplicated = True
                duplicated_count += 1
        duplicated_list.append([is_duplicated, ans])

    with open('./data/duplicated_matched_202402.csv', 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        
        for duplicated_content in duplicated_list:
            writer.writerow(duplicated_content)

        writer.writerow(["重复报告识别总数", duplicated_count])

def check_random_items():
    input_list = []
    with open('./data/data_with_type_202402.csv', 'r', newline='', encoding='utf-8') as csvfile:
    # 使用 csv.reader 读取 CSV 文件内容
        reader = csv.reader(csvfile)
        next(reader)

        for row in reader:
            input_list.append(row[7])

    data_list = []
    with open('./data/nvd_data_from_id_202402.csv', 'r', newline='', encoding='utf-8') as csvfile:
    # 使用 csv.reader 读取 CSV 文件内容
        reader = csv.reader(csvfile)
        next(reader)

        for row in reader:
            data_list.append(row[4])

    tp = 0
    fp = 0
    tn = 0
    fn = 0

    duplicated_list = []

    for i in range(1000):
        random_1 = random.randrange(0, len(input_list))
        random_2 = random.randrange(0, len(data_list))
        is_duplicated = False
        prompt = check_duplicated_report_prompt_generate(input_list[random_1], data_list[random_2])
        ans = call_llm(prompt)
        if ans == "是":
            is_duplicated = True
            if random_1 != random_2:
                fp += 1
            else:
                tp += 1
        elif ans == "否":
            is_duplicated = False
            if random_1 != random_2:
                tn += 1
            else:
                fn += 1
        duplicated_list.append([is_duplicated, ans, random_1, input_list[random_1], random_2, data_list[random_2]])

    with open('./data/duplicated_random_202402.csv', 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        
        for duplicated_content in duplicated_list:
            writer.writerow(duplicated_content)

        writer.writerow(["tp", tp, "fp", fp, "tn", tn, "fn", fn])

def api_detection(description):
    data_list = []
    with open('./data/nvd_data_from_id_202402.csv', 'r', newline='', encoding='utf-8') as csvfile:
    # 使用 csv.reader 读取 CSV 文件内容
        reader = csv.reader(csvfile)
        next(reader)

        for row in reader:
            data_list.append(row[4])
    
    entity_list = extract_input_entity([description])
    similar_indices = find_similar(entity_list[0][0:1], './data/entity_llm_202402.csv')
    is_duplicated = False
    duplicated_content = []
    for similar_index in similar_indices:
        similar_index = int(similar_index)

        prompt = report_detail_hint_prompt_generate(description, data_list[similar_index])
        ans = call_llm(prompt)
        prompt = check_duplicated_report_with_hint_prompt_generate(description, data_list[similar_index], ans)
        ans = call_llm(prompt)
    
        if ans == "是":
            is_duplicated = True
            duplicated_content.append(similar_index)

    return is_duplicated, duplicated_content, similar_indices

if __name__ == "__main__":
    check_duplicated()