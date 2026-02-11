package test

import (
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stretchr/testify/require"
)

const (
	LocalStackEndpoint = "http://localhost:4566"
	TestRegion         = "us-east-1"
)

// awsConfigFactory is set by init() in config_localstack_test.go or config_e2e_test.go.
var awsConfigFactory func() (aws.Config, error)

// endpointOverride is set by init() in the config files. Empty string means no override.
var endpointOverride string

// usePathStyle is set by init() in the config files. Only relevant for S3.
var usePathStyle bool

func getAWSConfig() (aws.Config, error) {
	return awsConfigFactory()
}

func newS3Client(cfg *aws.Config) *s3.Client {
	return s3.NewFromConfig(*cfg, func(o *s3.Options) {
		if endpointOverride != "" {
			o.BaseEndpoint = aws.String(endpointOverride)
		}
		o.UsePathStyle = usePathStyle
	})
}

func newDynamoDBClient(cfg *aws.Config) *dynamodb.Client {
	return dynamodb.NewFromConfig(*cfg, func(o *dynamodb.Options) {
		if endpointOverride != "" {
			o.BaseEndpoint = aws.String(endpointOverride)
		}
	})
}

const waitTimeout = 2 * time.Minute

func waitForS3Bucket(t *testing.T, client *s3.Client, bucketName string) {
	t.Helper()
	waiter := s3.NewBucketExistsWaiter(client)
	err := waiter.Wait(context.Background(), &s3.HeadBucketInput{
		Bucket: &bucketName,
	}, waitTimeout)
	require.NoError(t, err, "Timed out waiting for S3 bucket: %s", bucketName)
}

func waitForDynamoDBTable(t *testing.T, client *dynamodb.Client, tableName string) {
	t.Helper()
	waiter := dynamodb.NewTableExistsWaiter(client)
	err := waiter.Wait(context.Background(), &dynamodb.DescribeTableInput{
		TableName: &tableName,
	}, waitTimeout)
	require.NoError(t, err, "Timed out waiting for DynamoDB table: %s", tableName)
}
