#This script will combine all issues with the same Snyk vuln database ID
#into one Jira ticket sorted by a specific project tag
import requests
from requests.auth import HTTPBasicAuth
import json

#
## Variables
#
#Snyk Parameters (required)
#Add an org or group ID. If both are added, group will be used
organization_id = ''
group_id = ''
#Suggest using a group service account to ensure we have access to all orgs
snyk_token = ''
snyk_headers = {
  'Authorization': 'token '+snyk_token,
  'Content-Type': 'application/json'
}
snyk_tag_key = '' #The tag on your Snyk projects that we'll be sorting issues by

#Jira Parameters (required)
#Some additional info may be needed depending on your auth process for Jira
jira_project_id = ''
jira_api_url = 'https://<your-site>.atlassian.net/rest/api/2/issue'
jira_user = ''
jira_api_token = ''
jira_auth = HTTPBasicAuth(jira_user, jira_api_token)
jira_headers = {
  'Content-Type': 'application/json'
}

#Variables we'll use throughout the process
group_url = 'https://api.snyk.io/v1/group/'+group_id+'/orgs?perPage=100'
orgs = []
projects = [] #Each is a dict: {org: {name, id, slug}, projects: [{}, {}, ...]}
sorted_issues = {}
temp_org = {} #Used when sorting issues

#
## Functions
#
def fetch_data(method, org_id, proj_id):
  #Fetch issues if the project ID is supplied
  if proj_id:
    call_url = 'https://api.snyk.io/v1/org/'+org_id+'/project/'+proj_id+'/aggregated-issues'
  #Fetch projects if the project ID isn't supplied
  else:
    call_url = 'https://api.snyk.io/rest/orgs/'+org_id+'/projects'

  response = requests.request(method, call_url, headers=snyk_headers, data={})

  if response.status_code == 200:
    r_json = response.json()
    #We need the org slug name to build a link later
    if not proj_id:
      org_url = (
        'https://api.snyk.io/rest/orgs/'+org_id+
        '?version=2022-08-12~experimental'
      )
      org_rep = requests.request('GET', org_url, headers=snyk_headers, data={})
      org_json = org_rep.json()
      r_json['org']['slug'] = org_json['data']['attributes']['slug']
      projects.append(r_json)
    else:
      return r_json

def sort_issues():
  for project in temp_org['projects']:
    verify_tags(project)

def verify_tags(project):
  if project['tags']:
    for tag in project['tags']:
      if tag['key'] == snyk_tag_key:
        curr_tag = tag['value']
        #Create the new key/value if not already in sorted_issues
        if curr_tag not in sorted_issues:
          sorted_issues[curr_tag] = {}

        #Time to grab the project's issues
        issues = fetch_data('POST', temp_org['org']['id'], project['id'])
        #Go through the issues and add their links to sorted_issues
        add_issue_links(issues, curr_tag, project['id'])

def add_issue_links(issues, curr_tag, proj_id):
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
      'https://app.snyk.io/org/'+temp_org['org']['slug']+
      '/project/'+proj_id+'#issue-'+issue_id
    )
    sorted_issues[curr_tag][issue_id]['issue_links'].append(i_link)

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
    temp_org = org
    sort_issues()

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
      'POST', jira_api_url, headers=jira_headers, auth=jira_auth,  data=payload
    )

    #Here are two print lines if you would like to track the progress
    #or need to debug
    #print(t_response.status_code)
    #print(t_response.text)
