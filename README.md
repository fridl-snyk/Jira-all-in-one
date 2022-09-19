# Jira-all-in-one

Creates Jira tickets based on Snyk vulnerability database IDs (from a group or org) and sets the summary as the vulnerability title.
The body contains all issues in the project they came from that have the same vulnerability ID.
The vulnerabilities are initally sorted by a specific tag that is set on a Snyk project.  This does not grab projects without a tag or Snyk Code projects, but they can easily be added.

There's a possibility of having the same title for a ticket depending on how many times that issue appears between the tagged projects or if the vulnerability ID is different between them.
