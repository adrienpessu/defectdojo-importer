# DefectDojo-importer

A CLI for importing SARIF file from GitHub Advance Security to DefectDojo
You must set the GitHub configuration or the File configuration. 
In the GitHub configuration, only the last analysis will be loaded. 

## Configuration 

Github configuration
- `github-token`:  Token should be a personal access githubToken with security_events scope
- `github-instance`: instance is required and it should be the url of the github instance (optional, default is `api.github.com`)
- `github-organization`: GitHub organization (mandatory if `github-token` is set)
- `github-repository`: GitHub repository (mandatory if `github-token` is set)
- `github-branch`: GitHub repository branch (optional, default `master`)

File configuration
- `sarif-path`: Path to the SARIF file to import

DefectDojo configuration
- `dojo-token`: DefectDojo token (Mandatory)
- `dojo-instance`: DefectDojo instance URL (Mandatory)