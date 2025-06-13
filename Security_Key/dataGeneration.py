import re
import pandas as pd

def parse_trc_file(filepath):
    pattern = re.compile(
        r'^\s*(\d+)\)\s+'
        r'(\d+\.\d+)\s+'
        r'(Rx|Tx|Wrng)\s+'
        r'([0-9A-Fa-f]{4})\s+'
        r'(\d+)\s+'
        r'((?:[0-9A-Fa-f]{2}\s+){7}[0-9A-Fa-f]{2})'
    )

    rows = []
    with open(filepath, 'r') as file:
        for line in file:
            match = pattern.match(line)
            if match:
                message_no = int(match.group(1))
                time_offset = float(match.group(2))
                msg_type = match.group(3)
                msg_id = match.group(4)
                datalen = int(match.group(5))
                data_str = match.group(6)
                data = data_str.strip().split()
                rows.append([message_no, time_offset, msg_type, msg_id, datalen, data])

    df = pd.DataFrame(rows, columns=['message_no', 'time_offset', 'type', 'id', 'datalen', 'data'])
    return df
