package defectdojo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

type ImportScanService struct {
	client *Client
}

type ImportScan struct {
	ScanDate             *string   `json:"scan_date,omitempty"`
	MinimumSeverity      *string   `json:"minimum_severity,omitempty"`
	Active               *bool     `json:"active,omitempty"`
	Verified             *bool     `json:"verified,omitempty"`
	ScanType             *string   `json:"scan_type,omitempty"`
	EndpointToAdd        *int      `json:"endpoint_to_add,omitempty"`
	File                 *string   `json:"file,omitempty"`
	ProductTypeName      *string   `json:"product_type_name,omitempty"`
	ProductName          *string   `json:"product_name,omitempty"`
	EngagementName       *[]string `json:"engagement_name,omitempty"`
	Engagement           *int      `json:"engagement,omitempty"`
	TestTitle            *string   `json:"test_title,omitempty"`
	AutoCreateContext    *bool     `json:"auto_create_context,omitempty"`
	Lead                 *int      `json:"lead,omitempty"`
	Tags                 *[]string `json:"tags,omitempty"`
	CloseOldFindings     *bool     `json:"close_old_findings,omitempty"`
	PushToJira           *bool     `json:"push_to_jira,omitempty"`
	Environment          *string   `json:"environment,omitempty"`
	Version              *string   `json:"version,omitempty"`
	BuildId              *string   `json:"build_id,omitempty"`
	BranchTag            *string   `json:"branch_tag,omitempty"`
	CommitHash           *string   `json:"commit_hash,omitempty"`
	ApiScanConfiguration *int      `json:"api_scan_configuration,omitempty"`
	Service              *string   `json:"service,omitempty"`
	GroupBy              *string   `json:"group_by,omitempty"`
	Test                 *int      `json:"test,omitempty"`
	TestId               *int      `json:"test_id,omitempty"`
	EngagementId         *int      `json:"engagement_id,omitempty"`
	ProductId            *int      `json:"product_id,omitempty"`
	ProductTypeId        *int      `json:"product_type_id,omitempty"`
}

const (
	userAgent     = "go-defectdojo"
	mediaTypeJson = "application/json"
)

type Client struct {
	BaseURL    *url.URL
	Token      string
	HTTPClient *http.Client
	ImportScan *ImportScanService
}

type errorResponse struct {
	Code        int      `json:"code,omitempty"`
	Detail      string   `json:"detail,omitempty"`
	Description []string `json:"description,omitempty"`
	Message     string   `json:"message,omitempty"`
}

func SendSarifToDefectDojo(url string, token string, engagement int, sarif string) {

	client := &http.Client{
		Timeout: time.Minute,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
		},
	}

	log.Printf("URL: %s", url)

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

func NewDojoClient(dojourl string, token string, httpClient *http.Client) (*Client, error) {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	if len(dojourl) == 0 {
		return nil, errors.New("NewDojoClient: cannot create client, URL string is empty")
	}

	baseurl, err := url.Parse(dojourl + "/api/v2")
	if err != nil {
		return nil, fmt.Errorf("NewDojoClient: cannot parse URL: %w", err)
	}

	c := &Client{
		BaseURL:    baseurl,
		Token:      token,
		HTTPClient: httpClient,
	}

	c.ImportScan = &ImportScanService{client: c}

	return c, nil
}

func (c *Client) sendRequest(req *http.Request, v interface{}) error {
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", mediaTypeJson)

	if len(c.Token) > 0 {
		req.Header.Set("Authorization", fmt.Sprintf("Token %s", c.Token))
	}

	if len(req.Header.Get("Content-Type")) == 0 {
		req.Header.Set("Content-Type", mediaTypeJson)
	}

	//fmt.Println(req)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("sendRequest: cannot send request: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusBadRequest {
		errorResp := errorResponse{
			Code: res.StatusCode,
		}
		if err = json.NewDecoder(res.Body).Decode(&errorResp); err == nil {
			return fmt.Errorf("sendRequest: API error: %v", errorResp)
		}
		return fmt.Errorf("sendRequest: unknown error, status code: %d", res.StatusCode)
	}

	if err = json.NewDecoder(res.Body).Decode(v); err != nil {
		return fmt.Errorf("sendRequest: cannot decode reponse: %w", err)
	}

	return nil
}

type importScanMap map[string]string

func (c *ImportScanService) Create(ctx context.Context, m *ImportScan) (*ImportScan, error) {
	path := fmt.Sprintf("%s/import-scan/", c.client.BaseURL)

	up, err := structTagToMap(*m)
	if err != nil {
		return nil, err
	}
	req, err := newFileUploadRequest(path, &up)
	if err != nil {
		return nil, err
	}

	req = req.WithContext(ctx)

	res := new(ImportScan)
	if err := c.client.sendRequest(req, &res); err != nil {
		return nil, err
	}

	return res, nil
}

func newFileUploadRequest(uri string, params *importScanMap) (*http.Request, error) {
	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)

	for key, val := range *params {
		if key == "file" {
			part, err := writer.CreateFormFile(key, filepath.Base("github_sarif.json"))
			if err != nil {
				return nil, err
			}
			_, err = part.Write([]byte(val))
			if err != nil {
				return nil, err
			}
		} else {
			_ = writer.WriteField(key, val)
		}
	}

	err := writer.Close()
	if err != nil {
		return nil, err
	}

	r, err := http.NewRequest("POST", uri, body)
	if err != nil {
		return nil, err
	}
	//fmt.Println(writer.FormDataContentType())
	r.Header.Set("Content-Type", writer.FormDataContentType())

	return r, nil
}

func structTagToMap(in interface{}) (importScanMap, error) {
	m := make(importScanMap)

	v := reflect.ValueOf(in)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	t := v.Type()

	for i := 0; i < v.NumField(); i++ {

		tag := strings.Split(t.Field(i).Tag.Get("json"), ",")[0]
		if len(tag) == 0 {
			return nil, errors.New("tag not found")
		}

		value := v.Field(i).Interface()
		if v.Field(i).IsZero() {
			continue
		}
		if v.Field(i).Kind() == reflect.Ptr {
			value = v.Field(i).Elem()
		}

		m[tag] = fmt.Sprintf("%v", value)
	}

	return m, nil
}
