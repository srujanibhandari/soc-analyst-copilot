import pandas as pd


def load_logs(file_path):
    logs = pd.read_csv(file_path)
    return logs