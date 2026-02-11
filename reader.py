import csv
def read_log_file(path_file):
    with open(path_file, "r") as f:
        log_list = [line for line in csv.reader(f)]
        return log_list