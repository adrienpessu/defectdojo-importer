module github.com/adrienpessu/defectdojo-import-lambda

go 1.14

require (
	github.com/aws/aws-lambda-go v1.15.0
	github.com/aws/aws-sdk-go v1.34.0
)

require github.com/adrienpessu/defectdojo-importer/libs/defectdojo v0.0.0

require github.com/adrienpessu/defectdojo-importer/libs/sarif v0.0.0

replace github.com/adrienpessu/defectdojo-importer/libs/defectdojo => ./../../libs/defectdojo

replace github.com/adrienpessu/defectdojo-importer/libs/sarif => ./../../libs/sarif
