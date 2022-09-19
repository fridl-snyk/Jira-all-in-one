#This script will combine all issues with the same Snyk vuln database ID
#into one Jira ticket sorted by a specific project tag
from pickle import FALSE
import requests
import json

#
## Variables
#
#Snyk Parameters (required)
#Add a org or group ID. If both are added, group will be used
organization_id = ''
group_id = ''
#Suggest using a group service account to ensure we have access to all orgs
snyk_token = ''
snyk_headers = {
  'Authorization': 'token '+snyk_token,
  'Content-Type': 'application/json'
}

#Jira Parameters (required)
#The link below goes over the authorization property for jira_auth
#https://developer.atlassian.com/cloud/jira/platform/basic-auth-for-rest-apis
#Some additional info may be needed depending on your auth process for Jira
jira_project_id = ''
jira_api_url = "https://<your-site>.atlassian.net/rest/api/2/issue"
jira_auth = ''
jira_headers = {
  'Authorization': 'Basic '+jira_auth,
  'Content-Type': 'application/json',
}

#Variables we'll use throughout the process
group_url = 'https://api.snyk.io/api/v1/group/'+group_id+'/orgs?perPage=100'
orgs = []
projects = [] #Each is a dict: {org: {name, id, slug}, projects: [{}, {}, ...]}
sorted_issues = {}

#
## Functions
#
def fetch_data(method, org_id, proj_id):
  global projects
  base_url = 'https://app.snyk.io/api/v1/org/'+org_id

  #Fetch issues if the project ID is supplied
  if proj_id:
    call_url = base_url+'/project/'+proj_id+'/aggregated-issues'
  #Fetch projects if the project ID isn't supplied
  else:
    call_url = base_url+'/projects'

  response = requests.request(method, call_url, headers=snyk_headers, data={})

  if response.status_code == 200:
    r_json = response.json()
    #We need the org slug name to build a link later
    if not proj_id:
      r_json['org']['slug'] = org['slug']
      projects.append(r_json)
    else:
      return r_json

#
## Snyk Process
#
#Start by fetching the projects for your group if group_id has a value
if group_id:
  response = requests.request('GET', group_url, headers=snyk_headers, data={})

  if response.status_code == 200:
    orgs = response.json()['orgs']

#Fetch the projects that each org contains and populate projects
#with the results
if orgs:
  for org in orgs:
    if org['id']:
      fetch_data('POST', org['id'], '')
elif organization_id:
  fetch_data('POST', organization_id, '')

#With projects populated we can get a list of their issues
#using the org id and project id
#Sort the issues into a main category based on a tag then
#sort them in that category by their Snyk vuln id
if projects:
  for org in projects:
    for proj in org['projects']:
      #Need to find the tag we want to begin sorting issues by
      #The project tag property is a list of dictionaries
      if proj['tags']:
        for tag in proj['tags']:
          if tag['key'] == 'app': #The overall tag we'll be sorting by
            curr_tag = tag['value']
            #Create the new key/value if not already in sorted_issues
            if curr_tag not in sorted_issues:
              sorted_issues[curr_tag] = {}

            #Time to grab the project's issues
            issues = fetch_data('POST', org['org']['id'], proj['id'])
            #Loop through the issues and grab the data we want
            #then populate sorted_issues with that data
            for issue in issues['issues']:
              issue_id = issue['id']
              issue_data = issue['issueData']

              if issue_id not in sorted_issues[curr_tag]:
                sorted_issues[curr_tag][issue_id] = {
                  'url': issue_data['url'],
                  'title': issue_data['title'],
                  'issue_links': []
                }

              i_link = (
                'https://app.snyk.io/org/'+org['org']['slug']+
                '/project/'+proj['id']+'#issue-'+issue_id
              )
              sorted_issues[curr_tag][issue_id]['issue_links'].append(i_link)

#
## Jira Process
#
#Will have to add the other issue info in the body field of the main ticket
#which can include a link to the issue and any other additional info needed
#Confluence link about wiki markup for description
#https://confluence.atlassian.com/doc/confluence-wiki-markup-251003035.html
jira_labels = list(sorted_issues.keys())

for label in jira_labels:
  issue_ids = list(sorted_issues[label].keys())
  label_data = sorted_issues[label]

  for id in issue_ids:
    curr_issue = label_data[id]
    desc_text = (
      'Snyk Vulnerability Database ID: '+id+
      '\\\\ Snyk Vulnerability Database Link: ['+curr_issue['url']+']'
      ' \\\\ \\\\'
    )
    ticket = {
      'fields': {
        'project': {
          'key': jira_project_id
        },
        'summary': curr_issue['title'],
        'description': '',
        'issuetype': {
          'name': 'Bug'
        },
        'labels': [
          label
        ]
      }
    }

    for link in curr_issue['issue_links']:
      desc_text = desc_text+'* ['+link+'] \\\\ '

    ticket['fields']['description'] = desc_text
    payload = json.dumps(ticket)
    t_response = requests.request(
      'POST', jira_api_url, headers=jira_headers, data=payload
    )

    #Here are two print lines if you would like to track the progress
    #or need to debug
    #print(t_response.status_code)
    #print(t_response.text)
