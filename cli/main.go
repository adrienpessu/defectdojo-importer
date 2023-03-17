package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/adrienpessu/defectdojo-importer/libs/defectdojo"
	sarifModule "github.com/adrienpessu/defectdojo-importer/libs/sarif"
	"github.com/google/go-github/v50/github"
	"golang.org/x/oauth2"
	"io"
	"net/http"
	"os"
	"strings"
)

func main() {

	// GitHub configuration
	githubToken := flag.String("github-token", "", "Token should be a personal access githubToken with security_events scope")
	instance := flag.String("github-instance", "api.github.com", "instance is required and it should be the url of the github instance")
	organization := flag.String("github-organization", "", "GitHub organization")
	repository := flag.String("github-repository", "", "GitHub repository")
	branch := flag.String("github-branch", "master", "GitHub repository branch")

	// File Configuration
	sarifPath := flag.String("sarif-path", "", "Path to the SARIF file to import")

	sarifMitigation := flag.Bool("sarif-mitigation", false, "Mitigation to use for all findings")

	// DefectDojo configuration
	dojoToken := flag.String("dojo-token", "", "DefectDojo token")
	dojoInstance := flag.String("dojo-instance", "", "DefectDojo instance URL")
	dojoEngagement := flag.Int("dojo-engagement", 1, "DefectDojo engagement")

	flag.Parse()

	sarif := ""
	if isFlagPassed("github-token") {

		if !isFlagPassed("github-organization") || !isFlagPassed("github-repository") {
			fmt.Println("github-organization and github-repository are required when using github-token")
			return
		}

		ctx := context.Background()
		ts := oauth2.StaticTokenSource(
			&oauth2.Token{AccessToken: *githubToken},
		)
		tc := oauth2.NewClient(ctx, ts)
		client := github.NewClient(tc)

		opts := &github.AnalysesListOptions{
			ListOptions: github.ListOptions{},
			Ref:         branch,
		}

		// Get the analysis, by default the most recent comes first
		codeScanning, response, err := client.CodeScanning.ListAnalysesForRepo(ctx, *organization, *repository, opts)

		if err != nil && response.StatusCode != 200 {
			fmt.Println(err)
			return
		}

		analysis := *codeScanning[0]
		sarif = requestSarif(*githubToken, *instance, *organization, *repository, *analysis.ID)
	} else if isFlagPassed("sarif-path") {
		// read file in sarifPath and store it in the variable sarif
		file, err := os.Open(*sarifPath)
		if err != nil {
			fmt.Println(err)
			return
		}

		defer file.Close()

		sarifByte, err := io.ReadAll(file)
		if err != nil {
			fmt.Println(err)
			return
		}

		sarif = string(sarifByte)

	} else {
		fmt.Println("No SARIF file nor GitHub configuration provided")
		return
	}

	if *sarifMitigation {
		sarif = sarifModule.ImproveSarif(sarif)
	}

	defectdojo.SendSarifToDefectDojo(*dojoInstance, *dojoToken, *dojoEngagement, sarif)
}

func requestSarif(token string, instance string, owner string, repo string, analysisID int64) string {

	url := fmt.Sprintf("https://%v/repos/%v/%v/code-scanning/analyses/%v", instance, owner, repo, analysisID)
	method := "GET"

	payload := strings.NewReader(`{
	    "name": "web",
	    "active": true,
	    "events": [
	        "code_scanning_alert"
	    ],
	    "config": {
	        "url": "",
	        "content_type": "json",
	        "insecure_ssl": "0"
	    }
	}`)

	client := &http.Client{}
	req, err := http.NewRequest(method, url, payload)

	if err != nil {
		fmt.Println(err)
		return ""
	}
	req.Header.Add("Accept", "application/sarif+json")
	req.Header.Add("Authorization", "Bearer "+token)
	req.Header.Add("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Add("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return ""
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		fmt.Println(err)
		return ""
	}
	return string(body)
}

func isFlagPassed(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}
