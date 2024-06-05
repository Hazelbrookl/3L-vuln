import csv
from .lllchat import report_title_summarization_one_shot_prompt_generate, report_title_summarization_few_shot_prompt_generate,  call_llm

def summarization_test():
    input_list = []
    title_true = []
    with open('./data/data_with_type_202402.csv', 'r', newline='', encoding='utf-8') as csvfile:
    # 使用 csv.reader 读取 CSV 文件内容
        reader = csv.reader(csvfile)
        next(reader)

        for row in reader:
            input_list.append(row[7])
            title_true.append(row[0])
    
    title_pred = []

    for index, description in enumerate(input_list):
        prompt = report_title_summarization_few_shot_prompt_generate(description)
        ans = call_llm(prompt)

        title_pred.append(ans)

    with open('./data/summarization_few-shot_202402.csv', 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)

        for pred, true in zip(title_pred, title_true):
            writer.writerow([pred, true])

def api_summarization(description):
    prompt = report_title_summarization_few_shot_prompt_generate(description)
    ans = call_llm(prompt)
    return ans

if __name__ == "__main__":
    summarization_test()