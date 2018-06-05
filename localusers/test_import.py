import csv
import sys
import pprint


with open('localusers.csv', 'r') as file:
    reader = csv.DictReader(file, delimiter=';')
    user_list = []
    for line in reader:
        user_list.append(line)
        payload = {'user_id': line['userid'], 'username': line['username'], 'password': line['password'],
                   'role_name': line['rolename']}
        print(payload)