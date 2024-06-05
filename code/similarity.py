import spacy
import csv
import difflib
from .lllchat import dataset_entity_extract_prompt_generate, input_entity_extract_prompt_generate, call_llm

def extract_entity(text_list, mode):
    entity_list = []
    if mode == "spacy":
        nlp_en = spacy.load('en_core_web_sm')
        # nlp_zh = spacy.load('zh_core_web_sm')
        for index, text in enumerate(text_list):
            doc = nlp_en(text)
            for ent in doc.ents:
                entity_list.append([ent.text, ent.label_, index])
    elif mode == "llm":
        for index, text in enumerate(text_list):
            prompt = dataset_entity_extract_prompt_generate(text)
            res = call_llm(prompt).split('$')
            print(res)
            for ent in res:
                entity_list.append([ent, index])
    return entity_list

def extract_input_entity(text_list):
    entity_list = []
    for index, text in enumerate(text_list):
        prompt = input_entity_extract_prompt_generate(text)
        ent = call_llm(prompt)
        entity_list.append([ent, index])
    return entity_list
    
def find_similar(key_words, entity_file):
    entities = []
    numbers = []
    with open(entity_file, 'r', newline='', encoding='utf-8') as csvfile:
    # 使用 csv.reader 读取 CSV 文件内容
        reader = csv.reader(csvfile)
        for row in reader:
            entities.append(row[0].lower())
            numbers.append(row[1])
    
    similar_index = set()
    for key_word in key_words:
        matches = difflib.get_close_matches(key_word.lower(), entities, n=5, cutoff=0.3)
        if matches:
            for index, entity in enumerate(entities):
                if entity in matches:
                    similar_index.add(int(numbers[index]))

    return list(similar_index)

if __name__ == "__main__":
    text_list = []
    filename = './data/input_entity_llm_202402.csv'
    # with open(filename, 'r', newline='', encoding='utf-8') as csvfile:
    # # 使用 csv.reader 读取 CSV 文件内容
    #     reader = csv.reader(csvfile)
    #     next(reader)

    #     for row in reader:
    #         text_list.append(row[4])

    # with open(filename, 'r', newline='', encoding='utf-8') as csvfile:
    # # 使用 csv.reader 读取 CSV 文件内容
    #     reader = csv.reader(csvfile)
    #     next(reader)

    #     for row in reader:
    #         text_list.append(row[7])

    # entity_list = extract_input_entity(text_list)

    # with open('./data/input_entity_llm_202401.csv', 'w', newline='', encoding='utf-8') as csvfile:
    #     writer = csv.writer(csvfile)
        
    #     for entity in entity_list:
    #         writer.writerow(entity)



    with open(filename, 'r', newline='', encoding='utf-8') as csvfile:
    # 使用 csv.reader 读取 CSV 文件内容
        reader = csv.reader(csvfile)

        for row in reader:
            text_list.append(row[0])
    
    similar_list = []

    correct_count = 0
    total_length = 0

    for index, text in enumerate(text_list):
        similar_content = find_similar([text], './data/entity_llm_202402.csv')
        print(similar_content)
        if index in similar_content:
            correct_count += 1
        total_length += len(similar_content)
        similar_list.append(similar_content)
    
    with open('./data/similar_n5_202402.csv', 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        
        for similar_content in similar_list:
            writer.writerow(similar_content)

        writer.writerow([correct_count])
        writer.writerow([total_length/len(similar_list)])