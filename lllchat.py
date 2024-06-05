import requests
import csv
from openai import OpenAI
import os

def call_llm(content):
    max_retries = 10
    # 使用循环和 try-except 结构来重试函数
    for i in range(max_retries):
        try:
            response = requests.get("http://123.56.162.228:8888/v1/models")
            models = response.json()["data"]
            os.environ['OPENAI_API_KEY'] = "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"
            # 初始化客户端
            client = OpenAI(base_url="http://123.56.162.228:8888/v1")
            max_tokens = 4096
            # for model in models:
            #     print(model["id"])
            for model in models:
                if model["id"] != "qwen1.5_14b_chat":
                    continue
                model_name = model["id"]
                # print(f"Model: {model_name}")

                complete_msg = ""
                for message in client.chat.completions.create(
                    model=model_name,
                    messages=[
                        {"role": "user", "content": content[-max_tokens:]},
                    ],
                    max_tokens=max_tokens,
                    temperature=0.7,
                    stream=True,
                ):
                    if message.choices[0].delta.content:
                        complete_msg += message.choices[0].delta.content

                # print(complete_msg)
                return complete_msg
            break             # 如果成功，则退出循环
        except Exception as e:
            if i == max_retries - 1:
                raise Exception("重试次数已达上限，函数仍然失败")
            continue  # 如果是其他异常，继续重试
        
def translate_prompt_generate(info):

    prompt = f"""
这是一个漏洞报告的英文描述信息，请准确将其翻译成中文，注意不要翻译企业名、产品名等专有名词。
漏洞描述：{info}
"""
    return prompt

def input_entity_extract_prompt_generate(info):

    prompt = f"""
这是一个漏洞报告的描述信息，请从中尽可能完整地提取出最可能是受漏洞影响产品名的关键实体名称。
漏洞描述：{info}
请仅输出存在漏洞的完整产品名称，为一个完整的英文短语或单词，不要输出其他内容。
"""
    return prompt

def dataset_entity_extract_prompt_generate(info):

    prompt = f"""
这是一个漏洞报告的描述信息，请从中尽可能完整地提取出至少一个、至多三个可能是受漏洞影响产品名的关键实体名称。
漏洞描述：{info}
请仅输出关键实体名称，每个名称为一个完整的英文短语或单词，不同实体间用$分隔，你不需要一定找到三个答案，也不要输出其他内容。
"""
    return prompt

def check_duplicated_report_prompt_generate(info_1, info_2):

    prompt = f"""
以下有两个漏洞报告的描述，请判断它们是否指向一个完全相同的漏洞。
漏洞报告1：{info_1}
漏洞报告2：{info_2}
请根据其中出现漏洞的软件名称、版本信息和漏洞类型等信息，判断这两个报告是否指向一个相同的漏洞。注意，任何细微的差别都意味着可能是不同的漏洞。仅输出一个汉字是或否。
"""
    return prompt

def report_detail_hint_prompt_generate(info_1, info_2):

    prompt = f"""
以下有两个漏洞报告的描述，请提取出存在漏洞的开发商及软件名称、存在漏洞的版本、漏洞的类型和利用方式等信息。
漏洞报告1：{info_1}
漏洞报告2：{info_2}
请对这两个报告分别提取相应信息并输出，然后简要对比分析。
"""
    return prompt

def check_duplicated_report_with_hint_prompt_generate(info_1, info_2, hint):

    prompt = f"""
以下有两个漏洞报告的描述以及提取出的部分关键信息，请判断它们是否指向一个完全相同的漏洞。
漏洞报告1：{info_1}
漏洞报告2：{info_2}
提取的信息：{hint}
请参考出现漏洞的软件名称、版本信息和漏洞类型等信息，判断这两个报告是否指向一个相同的漏洞。
注意，任何细微的差别都意味着可能是不同的漏洞。仅输出一个汉字是或否，不要输出任何其他字符。
"""
    return prompt

def vulnerability_type_classification_zero_shot_prompt_generate(info, labels):

    prompt = f"""
以下是一个漏洞报告的描述，我要对其进行漏洞类型的多分类。
漏洞描述：{info}
分类标签如下列表所示：{labels}
对于输入的描述，根据其中与漏洞类型相关的文本，判断该漏洞的根源属于哪一类标签。
仅输出给定分类标签内的一个标签名称，如果无法判断，请输出汉字“无法判断”，绝对不要输出任何其他字符或多个标签。
"""
    return prompt

def vulnerability_type_classification_one_shot_prompt_generate(info, labels):

    prompt = f"""
以下是一个漏洞报告的描述，我要对其进行漏洞类型的多分类。
漏洞描述：{info}
分类标签如下列表所示：{labels}
对于输入的描述，根据其中与漏洞类型相关的文本，判断该漏洞的根源属于哪一类标签。
仅输出给定分类标签内的一个标签名称，如果无法判断，请输出汉字“无法判断”，绝对不要输出任何其他字符或多个标签。
示例：
输入：WordPress和WordPress plugin都是WordPress基金会的产品。WordPress是一套使用PHP语言开发的博客平台。该平台支持在PHP和MySQL的服务器上架设个人博客网站。WordPress plugin是一个应用插件。 WordPress plugin Advanced Access Manager 存在跨站脚本漏洞。攻击者利用该漏洞可以将恶意脚本注入网站。
回答：跨站脚本
"""
    return prompt

def vulnerability_type_classification_CoT_prompt_generate(info, labels):

    prompt = f"""
以下是一个漏洞报告的描述，我要对其进行漏洞类型的多分类。
漏洞描述：{info}
分类标签如下列表所示：{labels}
对于输入的描述，首先寻找文本中是否包含指明漏洞类型的分类标签；否则根据其中与漏洞类型相关的文本，判断该漏洞的根源属于哪一类标签。
仅输出给定分类标签内的一个标签名称，如果无法判断，请输出汉字“无法判断”，绝对不要输出任何其他字符或多个标签。
"""
    return prompt

def report_title_summarization_one_shot_prompt_generate(info):

    prompt = f"""
以下是一个漏洞报告的描述，请提炼关键信息拟定标题。
漏洞描述：{info}
对于输入的漏洞描述，为该漏洞报告拟定报告标题。请确保标题简明扼要，信息准确。绝对不要输出任何其他字符。
示例1：
输入：WordPress和WordPress plugin都是WordPress基金会的产品。WordPress是一套使用PHP语言开发的博客平台。该平台支持在PHP和MySQL的服务器上架设个人博客网站。WordPress plugin是一个应用插件。 WordPress plugin Advanced Access Manager 存在跨站脚本漏洞。攻击者利用该漏洞可以将恶意脚本注入网站。
回答：WordPress plugin Advanced Access Manager 跨站脚本漏洞
"""
    return prompt

def report_title_summarization_few_shot_prompt_generate(info):

    prompt = f"""
以下是一个漏洞报告的描述，请提炼关键信息拟定标题。
漏洞描述：{info}
对于输入的漏洞描述，为该漏洞报告拟定报告标题。请确保标题简明扼要，信息准确。绝对不要输出任何其他字符，无需包含版本信息。
示例1：
输入：WordPress和WordPress plugin都是WordPress基金会的产品。WordPress是一套使用PHP语言开发的博客平台。该平台支持在PHP和MySQL的服务器上架设个人博客网站。WordPress plugin是一个应用插件。 WordPress plugin Advanced Access Manager 存在跨站脚本漏洞。攻击者利用该漏洞可以将恶意脚本注入网站。
回答：WordPress plugin Advanced Access Manager 跨站脚本漏洞
示例2：
输入：GLPI是个人开发者的一款开源IT和资产管理软件。该软件提供功能全面的IT资源管理接口，你可以用它来建立数据库全面管理IT的电脑，显示器，服务器，打印机，网络设备，电话，甚至硒鼓和墨盒等。 GLPI 10.0.12之前版本存在跨站脚本漏洞，该漏洞源于报告页面包含跨站脚本漏洞，恶意 URL 可在报告页面上执行跨站脚本攻击。
回答：GLPI跨站脚本漏洞
示例3：
输入：IBM Operational Decision Manager是美国国际商业机器（IBM）公司的一种决策管理解决方案，用于帮助组织更好地管理和执行业务规则和决策。 IBM Operational Decision Manager 8.10.3 版本、8.10.4 版本、8.10.5.1 版本、8.11 版本、8.11.0.1 版本和 8.12.0.1 版本存在代码问题漏洞，该漏洞源于通过发送特制请求，可以在 SYSTEM 环境中执行任意代码。
回答：IBM Operational Decision Manager 代码问题漏洞
示例4：
输入：QNAP Systems QuTScloud等都是中国威联通科技（QNAP Systems）公司的产品。QNAP Systems QuTScloud是一种 QNAP NAS 操作系统的云端优化版本。QNAP Systems QTS是一个入门到中阶QNAP NAS 使用的操作系统。QNAP Systems QuTS hero是一个操作系统。 QNAP 多款产品存在命令注入漏洞，该漏洞源于存在操作系统命令注入漏洞。该漏洞可能允许经过身份验证的管理员通过网络执行命令。以下产品及版本受到影响：QTS 5.1.4.2596 版本之前，QuTS hero h5.1.4.2596 版本之前，QuTScloud c5.1.5.2651 版本之前。
回答：QNAP 多款产品命令注入漏洞
"""
    return prompt

def cvss_metrics_description_prompt_generate(metric):

    prompt = f"""
{metric}是CVSS3.1的指标之一，请先解释指标含义，再列举其取值并分别解释，不要输出其他内容。
示例：
CVSS 3.1 中的攻击向量（Attack Vector）是用于描述攻击者发起攻击的途径的指标，它表示攻击者与受影响组件之间的交互方式。攻击向量的取值及其解释如下：
网络（Network）： 攻击者通过网络连接到目标系统来发起攻击。这种情况下，攻击者无需直接与目标系统进行物理接触。例如，利用远程漏洞执行远程代码攻击。
局域网（Adjacent_Network）： 攻击者需要通过本地网络或物理接入点（例如，通过无线网络或本地以太网）来与目标系统进行交互，但不需要特殊的网络访问权限。例如，通过局域网攻击或通过物理接入点攻击。
本地（Local）： 攻击者必须已经本地（即在目标系统上）获得访问权限，才能发起攻击。这意味着攻击者必须能够直接访问目标系统，通常通过本地用户帐户或物理访问。例如，利用本地漏洞提升权限。
物理（Physical）： 攻击者需要物理接触目标系统才能发起攻击，例如，通过接触目标系统的设备端口或USB接口。这种攻击方式通常需要攻击者直接接触受影响设备。
"""
    return prompt

def vulnerability_severity_evaluation_prompt_generate(info, metric, hint, values, examples):

    defaults = {"攻击向量(Attack Vector, AV)": "无法判断", "攻击复杂度(Attack Complexity, AC)": "LOW", "权限要求(Privileges Required, PR)": "NONE", "用户交互(User Interaction,UI)": "NONE", 
           "作用域(Scope, S)": "", "机密性影响(Confidentiality Impact, C)": "", "完整性影响(Integrity Impact, I)": "", "可用性影响(Availability Impact, A)": ""}

    prompt = f"""
以下是一个漏洞报告的描述，请预测其CVSS3.1评分中的{metric}指标取值。
漏洞描述：{info}
指标提示：{hint}
可选取值：{values}
取值示例：{examples}
请根据描述中的相关内容和指标含义的提示，并分析参考相同类型漏洞的指标取值的一些漏洞描述，仅从可选取值中输出一个最可能的取值名称。如果难以判断结果，输出{defaults[metric]}。
"""
    return prompt

def dataset_metric_hint_extract_prompt_generate(info, metric, values, value, hint):

    examples_av = f"""
示例1
漏洞描述："AAM Advanced Access Manager—Restricted Content, Users & Roles, Enhanced Security and More中的网页生成过程中输入的不正确中和漏洞允许存储XSS（“跨站脚本”）。此问题影响Advanced Access Manager版本从n/a到6.9.18。远程(NETWORK)"
回答：网页生成时可被外部进攻。
示例2
漏洞描述："Dell PowerScale OneFS版本9.0.0.x至9.6.0.x包含一个关键功能缺少身份验证的漏洞。低特权的本地恶意用户可能会利用此漏洞获得提升的访问权限。本地(LOCAL)"
回答：错误权限的获取由本地用户发起。
示例3
漏洞描述："IBM Tivoli Application Dependency Discovery Manager 7.3.0.0至7.3.0.10可能允许组织本地网络上的攻击者因未经授权的API访问而升级其权限。局域网(ADJACENT_NETWORK)"
回答：在本地网络上获取了不当权限。
示例4
漏洞描述："可以从HID iCLASS SE读卡器配置卡中提取敏感数据。这可能包括凭据和设备管理员密钥。物理(PHYSICAL)"
回答：读卡器设备出现漏洞导致信息泄露。
"""
    examples_ac = f"""
示例1
漏洞描述："AAM Advanced Access Manager—Restricted Content, Users & Roles, Enhanced Security and More中的网页生成过程中输入的不正确中和漏洞允许存储XSS（“跨站脚本”）。此问题影响Advanced Access Manager版本从n/a到6.9.18。低(LOW)"
回答：攻击者可在页面生成时直接进行跨站脚本攻击。
示例2
漏洞描述："Pixee Java Code Security Toolkit是一组旨在帮助保护Java代码安全的安全API。`ZipSecurity#isBelowCurrentDirectory`易受部分路径遍历绕过的攻击。要易受绕过的攻击，应用程序必须使用工具包版本<=1.1.1.1，将ZipSecurity用作防止路径遍历的保护，并具有漏洞利用路径。尽管该控件仍然保护攻击者不将应用程序路径转义到更高级别的目录（例如/etc/），但它将允许“转义”到兄弟路径。例如，如果您的运行路径是/my/app/path，攻击者可以导航到/my/app/path其他路径。此漏洞已在1.1.2中修补。高(HIGH)"
回答：攻击者需要了解目录结构并掌握绕过防护的方法。
"""
    examples_pr = f"""
"""
    examples_ui = f"""
示例1
漏洞描述："AAM Advanced Access Manager—Restricted Content, Users & Roles, Enhanced Security and More中的网页生成过程中输入的不正确中和漏洞允许存储XSS（“跨站脚本”）。此问题影响Advanced Access Manager版本从n/a到6.9.18。有交互(REQUIRED)"
回答：存储型跨站脚本攻击一般需要用户通过http获取数据。
示例2
漏洞描述："Crafatar提供基于皮肤的Minecraft化身，用于外部应用程序。可以从服务器请求“lib/public/”目录之外的文件。运行在Cloudflare（包括crafatar.com）后面的实例不受影响。README中显示的使用Docker容器的实例会受到影响，但只能读取容器中的文件。默认情况下，容器中的所有文件也可以在此存储库中找到，并且不是机密文件。2.1.5中修补了此漏洞。无交互(NONE)"
回答：服务端路径遍历漏洞导致文件外泄，不需要用户交互。
"""
    examples = {"攻击向量(Attack Vector, AV)": examples_av, "攻击复杂度(Attack Complexity, AC)": examples_ac, "权限要求(Privileges Required, PR)": examples_pr, "用户交互(User Interaction,UI)": examples_ui, 
           "作用域(Scope, S)": "", "机密性影响(Confidentiality Impact, C)": "", "完整性影响(Integrity Impact, I)": "", "可用性影响(Availability Impact, A)": ""}
    
    prompt = f"""
以下是一个漏洞报告的描述。
漏洞描述：{info}
关注指标：{metric}
可选取值：{values}
实际取值：{value}
参照示例回答找到与是否需要用户交互相关的信息，务必确保输出在20字以内，不要输出实际指标取值。
{examples[metric]}
"""
    return prompt

def dataset_keyword_extract_prompt_generate(info, metric, values, value, hint):

    prompt = f"""
以下是一个漏洞报告的描述，请输出与其CVSS{metric}指标取值结果为{value}相关的关键词。
漏洞描述：{info}
可选取值：{values}
指标提示：{hint}
请根据描述中的相关内容和指标含义的提示，分析哪些词可能隐含了影响其实际取值的信息。仅输出找到的关键单词或短语，每个用$分隔，不要输出其他内容和公司名、产品名、产品版本等无关信息。
示例1：
"Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in AAM Advanced Access Manager – Restricted Content, Users & Roles, Enhanced Security and More allows Stored XSS.This issue affects Advanced Access Manager – Restricted Content, Users & Roles, Enhanced Security and More: from n/a through 6.9.18."
攻击向量(Attack Vector, AV)取值为远程(Network)
XSS$Cross-site Scripting$Web Page Generation
示例2：
"Dell PowerScale OneFS versions 9.0.0.x through 9.6.0.x contains a missing authentication for critical function vulnerability. A low privileged local malicious user could potentially exploit this vulnerability to gain elevated access."
攻击向量(Attack Vector, AV)取值为本地(LOCAL)
local$user$
"""
    return prompt

def evaluation_format_prompt_generate(ans, metric, values):

    prompt = f"""
以下是对cvss{metric}指标取值的判断和分析文本，请从中提取出最终的答案。
分析：{ans}
可选取值格式：{values}
从可选取值中选择最符合分析结果的一个取值输出，不要输出不可选的取值和其他字符。输出前不要加“答案：”等任何前缀。
"""
    return prompt

if __name__ == "__main__":
    prompt = input_entity_extract_prompt_generate()
    prompt= dataset_entity_extract_prompt_generate("Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in AAM Advanced Access Manager – Restricted Content, Users & Roles, Enhanced Security and More allows Stored XSS.This issue affects Advanced Access Manager – Restricted Content, Users & Roles, Enhanced Security and More: from n/a through 6.9.18.")
    call_llm(prompt)