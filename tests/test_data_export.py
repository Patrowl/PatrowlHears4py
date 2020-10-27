from config import api
from datetime import datetime

# Get data info
print(api.get_data_info())

# Export data
ts_epoch = datetime(2020, 1, 1, 0, 0).strftime('%s')
print(api.export_data(limit=1, since=ts_epoch))
