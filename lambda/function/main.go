package main

import (
	"context"
	"encoding/json"
	"github.com/adrienpessu/defectdojo-importer/libs/defectdojo"
	sarifModule "github.com/adrienpessu/defectdojo-importer/libs/sarif"
	"github.com/aws/aws-lambda-go/events"
	runtime "github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/s3"
	"io"
	"log"
	"os"
)

var client = lambda.New(session.New())

func callLambda() (string, error) {
	input := &lambda.GetAccountSettingsInput{}
	req, resp := client.GetAccountSettingsRequest(input)
	err := req.Send()
	output, _ := json.Marshal(resp.AccountUsage)
	return string(output), err
}

func handleRequest(ctx context.Context, event events.S3Event) (string, error) {
	// event

	bucketName := event.Records[0].S3.Bucket.Name
	key := event.Records[0].S3.Object.Key

	// get the object on the AWS S3 bucket
	sess := session.Must(session.NewSession())
	svc := s3.New(sess)
	result, err := svc.GetObject(&s3.GetObjectInput{
		Bucket: &bucketName,
		Key:    &key,
	})
	if err != nil {
		log.Printf(err.Error())
		return "ERROR", err
	}
	// read the object
	body, err := io.ReadAll(result.Body)
	if err != nil {
		log.Printf(err.Error())
		return "ERROR", err
	}
	// convert to string
	sarif := string(body)

	sarif = sarifModule.ImproveSarif(sarif)

	defectdojo.SendSarifToDefectDojo(os.Getenv("DEFECT_DOJO_URL"), os.Getenv("DEFECT_DOJO_TOKEN"), 1, sarif)

	return "OK", nil
}

func main() {
	runtime.Start(handleRequest)
}
