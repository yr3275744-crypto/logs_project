from reader import read_log_file
log_list = read_log_file(r"C:\Users\יצחק ריינר\my_python\projects\logs_project\network_traffic.log")

def search_external_ip(log_list:list):
    external_ip = [list[1] for list in log_list if not list[1].startswith("192.168") and not list[1].startswith("10.")]
    return external_ip

def search_sensitive_port_lines(log_list:list):
    sensitive_port_lines = [line for line in log_list if line[3] == "22" or line[3] == "23" or line[3] == "3389"]
    return sensitive_port_lines

def search_big_size_lines(log_list:list):
    big_size_lines = [line for line in log_list if int(line[5]) > 5000]
    return big_size_lines

def add_size_flage(log_list:list):
    with_size_flage_list = [line + ["LARGE"] if int(line[5]) > 5000 else line + ["NORMAL"] for line in log_list]
    return with_size_flage_list

def counting_num_requests(log_list:list):
    num_of_requests = {}
    for line in log_list:
        if line[1] in num_of_requests:
            num_of_requests[line[1]] += 1
        else:
            num_of_requests[line[1]] = 1
    return num_of_requests

def protocol_port_aranging(log_list:list):
    protocol_port_arrangement = {line[3]:line[4] for line in log_list}
    return protocol_port_arrangement
#בחרתי לכתוב את הפונקציה להלן כך, כדי למעט הרבה סיבוכיות של חיפוש ברשימות שיוצאות מהפונקציות הקודמות. 
#בדיעבד הבנתי שעדיף היה לעשות בשורה אחת, ובנוסף הקוד היה דינמי יותר מאשר בצורה שכתבתיו. לכל אופציה המעלות והחסרונות שלה
def return_suspicions_types(log_list:list):
    suspicions_types_per_ip = {}
    for line in log_list:
        if line[1] not in suspicions_types_per_ip:
            suspicions_types_per_ip[line[1]] = []
        if not line[1].startswith("192.168") and not line[1].startswith("10."):
            suspicions_types_per_ip[line[1]].append("EXTERNAL IP")
        if line[3] == "22" or line[3] == "23" or line[3] == "3389":
             suspicions_types_per_ip[line[1]].append("SENSITIVE_PORT")
        if int(line[5]) > 5000:
            suspicions_types_per_ip[line[1]].append("LARGE_PACKET")
        if 0 < int(line[0][11:13]) < 6:
            suspicions_types_per_ip[line[1]].append("NIGHT_ACTIVITY")
        suspicions_types_per_ip[line[1]] = set(suspicions_types_per_ip[line[1]])
        suspicions_types_per_ip[line[1]] = list(suspicions_types_per_ip[line[1]])
    return suspicions_types_per_ip

def filtering_suspicions(suspicions_dict:dict):
    filtered_suspicions = {item[0]:item[1] for item in suspicions_dict.items() if len(item[1]) > 2}
    return filtered_suspicions

hours = list(map(lambda line: int(line[0][11:13]), log_list))
size_as_kb = list(map(lambda line: int(line[5]) / 1024, log_list))
sensitive_port_lines = list(filter(lambda line: True if line[3] == "22" else True if line[3] == "23" else True if line[3] == "3389" else False, log_list))
night_activity_lines = list(filter(lambda line: True if  0 < int(line[0][11:13]) < 6 else False, log_list))
