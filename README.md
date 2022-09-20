# Jira-all-in-one

Creates Jira tickets based on Snyk vulnerability database IDs (from a group or org) and uses the vulnerability title as the ticket summary.
The body contains all issue links (that send you to the filtered project so you see the specific vuln) that have the same vulnerability ID, as well as the vuln ID and database link.
The vulnerabilities are initally sorted by a specific tag that is set on a Snyk project.  This does not grab projects without a tag or Snyk Code projects, but they can easily be added.

There's a possibility of having the same title for a ticket depending on how many times that issue appears between the tagged projects or if the vulnerability ID is different between them.
