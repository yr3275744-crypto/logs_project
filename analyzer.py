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