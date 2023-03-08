package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/go-github/v50/github"
	"golang.org/x/oauth2"
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

		sarifByte, err := io.ReadAll(file)
		if err != nil {
			fmt.Println(err)
			return
		}

		sarif = string(sarifByte)

		defer file.Close()

	} else {
		fmt.Println("No SARIF file nor GitHub configuration provided")
		return
	}

	if *sarifMitigation {
		var mitigations = make(map[string]string)
		var structuredSarif Sarif
		json.Unmarshal([]byte(sarif), &structuredSarif)
		for _, run := range structuredSarif.Runs {
			for _, rule := range run.Tool.Driver.Rules {
				mitigations[rule.ID] = rule.Help.Text
			}
		}

		var runs = make([]Runs, 0)

		for _, run := range structuredSarif.Runs {
			var results []Result
			for _, result := range run.Results {

				value, ok := mitigations[result.RuleID]
				if !ok {
					results = append(results, result)
				} else {
					fixesDescription := &FixesDescription{
						Text: value,
					}

					fixes := &Fixes{
						Description: *fixesDescription,
					}

					fixesArray := []Fixes{*fixes}

					result2 := result
					result2.Fixes = fixesArray
					results = append(results, result2)
				}

			}
			run.Results = results
			runs = append(runs, run)
		}
		structuredSarif.Runs = runs

		json, err := json.Marshal(structuredSarif)
		if err != nil {
			fmt.Println(err)
			return
		}
		sarif = string(json)

		os.WriteFile("test.json", []byte(sarif), 0644)

	}

	sendSarifToDefectDojo(*dojoInstance, *dojoToken, *dojoEngagement, sarif)
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

func sendSarifToDefectDojo(url string, token string, engagement int, sarif string) {

	client := &http.Client{
		Timeout: time.Minute,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
		},
	}

	dj, err := NewDojoClient(url, token, client)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	ctx := context.Background()

	autoCreate := true
	scanType := "SARIF"

	environment := "Default"
	scan := &ImportScan{
		Engagement:        &engagement,
		Environment:       &environment,
		AutoCreateContext: &autoCreate,
		File:              &sarif,
		ScanType:          &scanType,
	}

	resp, err := dj.ImportScan.Create(ctx, scan)
	if err != nil {
		fmt.Println("main:", err)
		return
	}

	b, err := json.Marshal(resp)
	if err != nil {
		fmt.Println("main:", err)
		return
	}

	fmt.Println(string(b))
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

type Sarif struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []Runs `json:"runs"`
}

type Runs struct {
	Tool struct {
		Driver struct {
			Name            string `json:"name"`
			Organization    string `json:"organization"`
			SemanticVersion string `json:"semanticVersion"`
			Notifications   []struct {
				ID               string `json:"id"`
				Name             string `json:"name"`
				ShortDescription struct {
					Text string `json:"text"`
				} `json:"shortDescription"`
				FullDescription struct {
					Text string `json:"text"`
				} `json:"fullDescription"`
				DefaultConfiguration struct {
					Enabled bool `json:"enabled"`
				} `json:"defaultConfiguration"`
				Properties struct {
					Description string `json:"description"`
					ID          string `json:"id"`
					Kind        string `json:"kind"`
					Name        string `json:"name"`
				} `json:"properties,omitempty"`
				Properties0 struct {
					Tags        []string `json:"tags"`
					Description string   `json:"description"`
					ID          string   `json:"id"`
					Kind        string   `json:"kind"`
					Name        string   `json:"name"`
				} `json:"properties,omitempty"`
			} `json:"notifications"`
			Rules []struct {
				ID               string `json:"id"`
				Name             string `json:"name"`
				ShortDescription struct {
					Text string `json:"text"`
				} `json:"shortDescription"`
				FullDescription struct {
					Text string `json:"text"`
				} `json:"fullDescription"`
				DefaultConfiguration struct {
					Enabled bool   `json:"enabled"`
					Level   string `json:"level"`
				} `json:"defaultConfiguration,omitempty"`
				Help struct {
					Text     string `json:"text"`
					Markdown string `json:"markdown"`
				} `json:"help,omitempty"`
				Properties struct {
					Tags             []string `json:"tags"`
					Description      string   `json:"description"`
					ID               string   `json:"id"`
					Kind             string   `json:"kind"`
					Name             string   `json:"name"`
					Precision        string   `json:"precision"`
					ProblemSeverity  string   `json:"problem.severity"`
					SecuritySeverity string   `json:"security-severity"`
				} `json:"properties,omitempty"`
			} `json:"rules"`
		} `json:"driver"`
		Extensions []struct {
			Name            string `json:"name"`
			SemanticVersion string `json:"semanticVersion"`
			Locations       []struct {
				URI         string `json:"uri"`
				Description struct {
					Text string `json:"text"`
				} `json:"description"`
			} `json:"locations"`
		} `json:"extensions"`
	} `json:"tool"`
	Invocations []struct {
		ToolExecutionNotifications []struct {
			Message struct {
				Text string `json:"text"`
			} `json:"message"`
			Descriptor struct {
				ID    string `json:"id"`
				Index int    `json:"index"`
			} `json:"descriptor"`
			Properties struct {
				FormattedMessage struct {
					Text string `json:"text"`
				} `json:"formattedMessage"`
			} `json:"properties"`
			Locations []struct {
				PhysicalLocation struct {
					ArtifactLocation struct {
						URI       string `json:"uri"`
						URIBaseID string `json:"uriBaseId"`
						Index     int    `json:"index"`
					} `json:"artifactLocation"`
				} `json:"physicalLocation"`
			} `json:"locations,omitempty"`
			Level string `json:"level,omitempty"`
		} `json:"toolExecutionNotifications"`
		ExecutionSuccessful bool `json:"executionSuccessful"`
	} `json:"invocations"`
	Artifacts []struct {
		Location struct {
			URI       string `json:"uri"`
			URIBaseID string `json:"uriBaseId"`
			Index     int    `json:"index"`
		} `json:"location"`
	} `json:"artifacts"`
	Results           []Result `json:"results"`
	AutomationDetails struct {
		ID string `json:"id"`
	} `json:"automationDetails"`
	ColumnKind string `json:"columnKind"`
	Properties struct {
		MetricResults []struct {
			Rule struct {
				ID    string `json:"id"`
				Index int    `json:"index"`
			} `json:"rule"`
			RuleID    string `json:"ruleId"`
			RuleIndex int    `json:"ruleIndex"`
			Value     int    `json:"value"`
			Message   struct {
				Text string `json:"text"`
			} `json:"message,omitempty"`
			Baseline int `json:"baseline,omitempty"`
		} `json:"metricResults"`
		SemmleFormatSpecifier string `json:"semmle.formatSpecifier"`
	} `json:"properties"`
}

type Fixes struct {
	Description FixesDescription `json:"description"`
}

type FixesDescription struct {
	Text string `json:"text"`
}

type Result struct {
	RuleID    string `json:"ruleId"`
	RuleIndex int    `json:"ruleIndex"`
	Rule      struct {
		ID    string `json:"id"`
		Index int    `json:"index"`
	} `json:"rule"`
	Message struct {
		Text string `json:"text"`
	} `json:"message"`
	Locations []struct {
		PhysicalLocation struct {
			ArtifactLocation struct {
				URI       string `json:"uri"`
				URIBaseID string `json:"uriBaseId"`
				Index     int    `json:"index"`
			} `json:"artifactLocation"`
			Region struct {
				StartLine   int `json:"startLine"`
				StartColumn int `json:"startColumn"`
				EndColumn   int `json:"endColumn"`
			} `json:"region"`
		} `json:"physicalLocation"`
	} `json:"locations"`
	PartialFingerprints struct {
		PrimaryLocationLineHash               string `json:"primaryLocationLineHash"`
		PrimaryLocationStartColumnFingerprint string `json:"primaryLocationStartColumnFingerprint"`
	} `json:"partialFingerprints"`
	RelatedLocations []struct {
		ID               int `json:"id"`
		PhysicalLocation struct {
			ArtifactLocation struct {
				URI       string `json:"uri"`
				URIBaseID string `json:"uriBaseId"`
				Index     int    `json:"index"`
			} `json:"artifactLocation"`
			Region struct {
				StartLine   int `json:"startLine"`
				StartColumn int `json:"startColumn"`
				EndColumn   int `json:"endColumn"`
			} `json:"region"`
		} `json:"physicalLocation"`
		Message struct {
			Text string `json:"text"`
		} `json:"message"`
	} `json:"relatedLocations,omitempty"`
	CodeFlows []struct {
		ThreadFlows []struct {
			Locations []struct {
				Location struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI       string `json:"uri"`
							URIBaseID string `json:"uriBaseId"`
							Index     int    `json:"index"`
						} `json:"artifactLocation"`
						Region struct {
							StartLine   int `json:"startLine"`
							StartColumn int `json:"startColumn"`
							EndColumn   int `json:"endColumn"`
						} `json:"region"`
					} `json:"physicalLocation"`
					Message struct {
						Text string `json:"text"`
					} `json:"message"`
				} `json:"location"`
			} `json:"locations"`
		} `json:"threadFlows"`
	} `json:"codeFlows,omitempty"`
	Fixes []Fixes `json:"fixes,omitempty"`
}
