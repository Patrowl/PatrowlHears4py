from patrowlhears4py.api import PatrowlHearsApi


api = PatrowlHearsApi(
    url='http://localhost:3333',
    auth_token='774c5c9d7908a6d970be392cf54b20ddca1d0319'
)

print(api.get_data_info())
print(api.export_data_full(limit=1, since="2020-01-01"))
