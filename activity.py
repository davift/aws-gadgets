import boto3
import datetime
import json
import sys
from tabulate import tabulate

username_or_role = sys.argv[1]
if not username_or_role.startswith('arn:aws:'):
    is_username = True
else:
    is_username = False
window = sys.argv[2]

blue='\033[94m'
green='\033[92m'
red='\033[91m'
reset='\033[0m'

print('')
print(tabulate([[blue + 'CloudTrail Access Analysis' + reset]], tablefmt="simple"))

client = boto3.client('cloudtrail')

events = []
next_token = None
params = {
    'LookupAttributes': [
        {
            'AttributeKey': 'Username' if is_username == True else 'ResourceName',
            'AttributeValue': username_or_role
        },
    ],
    'StartTime': datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=int(window)),
    'EndTime': datetime.datetime.now(datetime.timezone.utc),
    'MaxResults': 50
}
while True:
    try:
        response = client.lookup_events(**params)
        events.extend(response['Events'])
        next_token = response.get('NextToken')
        if not next_token:
            break
        else:
            params['NextToken'] = next_token
    except Exception as e:
        print(f"Error retrieving events: {e}")
        break

errors = []
grants = []
if not events:
    print('')
    print("No events found for the specified user.")
    print('')
    exit()
else:
    for event in events:
        log_data = json.loads(event['CloudTrailEvent'])
        #print(log_data)
        if 'errorCode' in log_data:
            errors.append(log_data['eventName'])
        else:
            grants.append(log_data['eventName'])

print('')
print('User/Role:', username_or_role)
print('Activity: last', window, 'hours')
print('')
print(tabulate([["Total events found", blue + str(len(events)) + reset], ["Events with errors", red + str(len(errors)) + reset], ["Events with grants", green + str(len(grants)) + reset]], tablefmt="simple"))

if len(errors) > 0:
    print('')
    print(tabulate([[error] for error in list(set(errors))], headers=[red + "Denied Permission(s)" + reset], tablefmt="firstrow"))

if len(grants) > 0:
    print('')
    print(tabulate([[grant] for grant in list(set(grants))], headers=[green + "Granted Permission(s)" + reset], tablefmt="firstrow"))

print('')
exit()
