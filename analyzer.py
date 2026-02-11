def serech_external_ip(log_list:list):
    external_ip = [list[1] for list in log_list if not list[1].startswith("192.168") and not list[1].startswith("10.")]
    return external_ip