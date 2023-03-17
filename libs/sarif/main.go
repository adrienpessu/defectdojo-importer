package sarif

import (
	"encoding/json"
	"fmt"
)

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

func ImproveSarif(sarif string) string {
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
		return ""
	}
	sarif = string(json)
	return sarif
}
