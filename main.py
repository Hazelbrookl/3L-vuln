import streamlit as st
import pandas as pd
import os
import csv
from code.duplicated import api_detection
from code.summarization import api_summarization
from code.classification import api_classification, get_labels
from code.evaluation import api_evaluation
from code.BingAPI import api_search

MODE_MAIN = 0
MODE_DETECTION = 1
MODE_SUMMARIZATION = 2
MODE_CLASSIFICATION = 3
MODE_EVALUATION = 4

PAGE_FUNCTION = 0
PAGE_DATASET = 1
PAGE_HISTORY = 2
PAGE_DETAIL = 3
PAGE_SEARCH = 4

df1 = pd.read_csv('data/nvd_data_from_id_202402.csv')
df1 = df1.drop(['cwe-type'], axis=1)
df2 = pd.read_csv('data/data_with_type_202402.csv', usecols=['vuln-type', 'name'])
df = pd.concat([df2, df1], axis=1)
df.index += 1

df_history = pd.DataFrame()
if os.path.exists('data/history.csv'):
    df_history = pd.read_csv('data/history.csv')

def convert_df(df_input):
    return df_input.to_csv().encode('utf-8')

def make_clickable(url):
    return f'<a target="_blank" href="{url}">{str(url)}</a>'

def call_back_switchMode(mode):
    global description_input
    description_input = ""
    global type_input
    type_input = ""
    st.session_state.current_mode = mode

def call_back_switchPage(page):
    global description_input
    description_input = ""
    global type_input
    type_input = ""
    global index_input
    index_input = 1
    global search_input
    search_input = ""
    st.session_state.current_mode = MODE_MAIN
    st.session_state.current_page = page
    st.session_state.detail = None
    st.session_state.search_response = None

def call_back_viewDetail(detail):
    st.session_state.detail = detail
    st.session_state.current_mode = MODE_MAIN
    st.session_state.current_page = PAGE_DETAIL

def call_back_saveHistory(history):
    history['mode'] = [st.session_state.current_mode]
    history = pd.DataFrame.from_dict(history)
    global df_history
    df_history = pd.concat([df_history, history], axis=0)
    df_history.reset_index(drop=True, inplace=True)
    df_history.to_csv("data/history.csv", index=False)

def call_back_bingSearch(query):
    st.session_state.search_response = api_search(query)

if __name__ == "__main__":

    st.set_page_config(
        page_title='3L-vuln ',
        page_icon=' ',
    )

    with st.sidebar:
        st.title('3L漏洞报告处理大模型')
        st.markdown('---')
        st.markdown('此工具的介绍：\n- 原始存储漏洞报告主体来源为NVD，漏洞类型和标题字段来源于CNNVD\n- 支持对输入报告的重复检测、标题拟定、漏洞分类、危害评估等四个功能\n- 支持查看工具使用记录')
        col1, col2, col3= st.columns(3)
        col1.button("功能", on_click=lambda: call_back_switchPage(PAGE_FUNCTION))
        col2.button("数据", on_click=lambda: call_back_switchPage(PAGE_DATASET))
        col3.button("历史", on_click=lambda: call_back_switchPage(PAGE_HISTORY))
        col1, col2, col3= st.columns(3)
        col1.button("搜索", on_click=lambda: call_back_switchPage(PAGE_SEARCH))
        st.write("国家信息安全漏洞库(CNNVD)")
        st.write("https://www.cnnvd.org.cn/home/childHome/")
        st.write("National Vulnerability Database(NVD)")
        st.write("https://nvd.nist.gov/")
        st.write("CVSS3.1漏洞危害评估标准")
        st.write("https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator/")
        st.write("Common Vulnerabilities & Exposures(CVE)")
        st.write("https://cve.mitre.org/")
        st.write("Common Weakness Enumeration(CWE)")
        st.write("https://cwe.mitre.org/")
        st.write("Common Platform Enumeration(CWE)")
        st.write("https://cpe.mitre.org/")


    if "current_page" not in st.session_state:
        st.session_state.current_page = PAGE_FUNCTION

    if st.session_state.current_page == PAGE_FUNCTION:
              
        st.title("功能")

        col1, col2, col3, col4 = st.columns(4)

        col1.button("重复检测", on_click=lambda: call_back_switchMode(MODE_DETECTION))
        col2.button("标题拟定", on_click=lambda: call_back_switchMode(MODE_SUMMARIZATION))
        col3.button("漏洞分类", on_click=lambda: call_back_switchMode(MODE_CLASSIFICATION))
        col4.button("危害评估", on_click=lambda: call_back_switchMode(MODE_EVALUATION))

        if "current_mode" not in st.session_state:
            st.session_state.current_mode = MODE_MAIN

        if st.session_state.current_mode == MODE_MAIN:
            header_component = st.header("请选择功能")
        elif st.session_state.current_mode == MODE_DETECTION:
            header_component = st.header("重复检测")
        elif st.session_state.current_mode == MODE_SUMMARIZATION:
            header_component = st.header("标题拟定")
        elif st.session_state.current_mode == MODE_CLASSIFICATION:
            header_component = st.header("漏洞分类")
        elif st.session_state.current_mode == MODE_EVALUATION:
            header_component = st.header("危害评估")

        if st.session_state.current_mode != MODE_MAIN:
            description_input = st.text_input("输入漏洞描述", "")
            if st.session_state.current_mode == MODE_EVALUATION:
                labels =  get_labels()
                labels.insert(0, "其他")
                type_input = st.selectbox("输入漏洞类型", labels, 0, format_func=str)
                # type_input = st.text_input("输入漏洞类型", "")
            else:
                type_input = ""
        
            if st.button("submit"):
                if description_input != "":
                    if st.session_state.current_mode == MODE_DETECTION:
                        is_duplicated, duplicated_indices, similar_indices = api_detection(description_input)
                        if is_duplicated:
                            st.warning("该漏洞有疑似重复项！")
                        else:
                            st.success("该漏洞无疑似重复项！")
                        if len(duplicated_indices) > 0:
                            st.subheader("模型判重条目：")
                            duplicated_indices = [duplicated_index + 1 for duplicated_index in duplicated_indices]
                            df_duplicated = df.loc[duplicated_indices].reset_index(drop=True)
                            df_duplicated.index += 1
                            st.dataframe(df_duplicated, use_container_width=True)
                        if len(similar_indices) > 0:
                            st.subheader("实体匹配条目：")
                            similar_indices = [similar_index + 1 for similar_index in similar_indices]
                            df_similar = df.loc[similar_indices].reset_index(drop=True)
                            df_similar.index += 1
                            st.dataframe(df_similar, use_container_width=True)
                        history = {"description_input":[description_input], "is_duplicated":[is_duplicated], "duplicated_indices":[duplicated_indices], "similar_indices":[similar_indices]}
                        call_back_saveHistory(history)
                    elif st.session_state.current_mode == MODE_SUMMARIZATION:
                        vuln_title = api_summarization(description_input)
                        st.subheader("报告标题：")
                        st.code(vuln_title)
                        history = {"description_input":[description_input], "vuln_title":[vuln_title]}
                        call_back_saveHistory(history)
                    elif st.session_state.current_mode == MODE_CLASSIFICATION:
                        vuln_type = api_classification(description_input)
                        st.subheader("漏洞类型：")
                        st.code(vuln_type)
                        history = {"description_input":[description_input], "vuln_type":[vuln_type]}
                        call_back_saveHistory(history)
                    elif st.session_state.current_mode == MODE_EVALUATION:
                        if type_input != "":
                            vuln_metrics = api_evaluation(description_input, type_input)
                            st.subheader("危害评估：")
                            st.markdown("攻击向量(Attack Vector, AV):")
                            st.code(vuln_metrics[0])
                            st.markdown("攻击复杂度(Attack Complexity, AC):")
                            st.code(vuln_metrics[1])
                            st.markdown("权限要求(Privileges Required, PR):")
                            st.code(vuln_metrics[2])
                            st.markdown("用户交互(User Interaction,UI):")
                            st.code( vuln_metrics[3])
                            history = {"description_input":[description_input], "type_input":[type_input], "vuln_metrics":[vuln_metrics]}
                            call_back_saveHistory(history)
                        else:
                            st.error("请输入漏洞类型！")
                else:
                    st.error("请输入漏洞描述！")

    elif st.session_state.current_page == PAGE_DATASET:
        
        st.title("数据")
        st.dataframe(df, use_container_width=True, height=600)
        
        csv_download = convert_df(df)
        st.download_button(
            label="下载数据",
            data=csv_download,
            file_name='dataset_save.csv',
            mime='text/csv',
        )

    elif st.session_state.current_page == PAGE_HISTORY:

        st.title("历史")
        if df_history.empty:
            header_component = st.header("暂无历史记录")
        else:
            df_abstract = pd.DataFrame()
            df_abstract = df_history[['mode', 'description_input']].copy()
            mapping = {1: '重复检测', 2: '标题拟定', 3: '漏洞分类', 4: '危害评估'}
            df_abstract['mode'] = df_abstract['mode'].map(mapping)
            df_abstract.index += 1
            index_input = st.number_input(min_value=1,max_value=len(df_abstract),label="查找详情",placeholder="输入序号")
            st.button("view", on_click=lambda: call_back_viewDetail(df_history.loc[index_input - 1]))
            st.dataframe(df_abstract, use_container_width=True, height=500)
            csv_download = convert_df(df_history)
            st.download_button(
                label="下载历史",
                data=csv_download,
                file_name='history_save.csv',
                mime='text/csv',
            )

    elif st.session_state.current_page == PAGE_DETAIL:

        st.title("历史")

        df_detail = st.session_state.detail
        if df_detail is not None:
            st.subheader("漏洞描述")
            st.write(df_detail['description_input'])
            if df_detail['mode'] == MODE_DETECTION:
                is_duplicated = df_detail['is_duplicated']
                duplicated_indices = eval(df_detail['duplicated_indices'])
                similar_indices = eval(df_detail['similar_indices'])
                if is_duplicated:
                    st.warning("该漏洞有疑似重复项！")
                else:
                    st.success("该漏洞无疑似重复项！")
                if len(duplicated_indices) > 0:
                    st.subheader("模型判重条目：")
                    # duplicated_indices = [duplicated_index + 1 for duplicated_index in duplicated_indices]
                    df_duplicated = df.loc[duplicated_indices].reset_index(drop=True)
                    df_duplicated.index += 1
                    st.dataframe(df_duplicated, use_container_width=True)
                if len(similar_indices) > 0:
                    st.subheader("实体匹配条目：")
                    # similar_indices = [similar_index + 1 for similar_index in similar_indices]
                    df_similar = df.loc[similar_indices].reset_index(drop=True)
                    df_similar.index += 1
                    st.dataframe(df_similar, use_container_width=True)
            elif df_detail['mode'] == MODE_SUMMARIZATION:
                vuln_title = df_detail['vuln_title']
                st.subheader("报告标题：")
                st.code(vuln_title)
            elif df_detail['mode'] == MODE_CLASSIFICATION:
                vuln_type = df_detail['vuln_type']
                st.subheader("漏洞类型：")
                st.code(vuln_type)
            elif df_detail['mode'] == MODE_EVALUATION:
                st.subheader("漏洞类型")
                st.write(df_detail['type_input'])
                vuln_metrics = eval(df_detail['vuln_metrics'])
                st.subheader("CVSS3.1利用性指标评估结果：")
                st.markdown("攻击向量(Attack Vector, AV):")
                st.code(vuln_metrics[0])
                st.markdown("攻击复杂度(Attack Complexity, AC):")
                st.code(vuln_metrics[1])
                st.markdown("权限要求(Privileges Required, PR):")
                st.code(vuln_metrics[2])
                st.markdown("用户交互(User Interaction,UI):")
                st.code( vuln_metrics[3])
        else:
            st.subheader("Error")

    elif st.session_state.current_page == PAGE_SEARCH:

        st.title("搜索")
        search_input = st.text_input("输入查询内容", "")
        st.button("Go!", on_click=lambda: call_back_bingSearch(search_input))
        search_response = st.session_state.search_response
        if search_response is not None:
            df_search = pd.DataFrame(search_response, columns=['title', 'url'])
            df_search.index += 1
            df_search['url'] = df_search['url'].apply(make_clickable)
            df_search = df_search.to_html(escape=False)
            st.write(df_search, unsafe_allow_html=True)


