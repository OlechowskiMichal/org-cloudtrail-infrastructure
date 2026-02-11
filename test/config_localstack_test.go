//go:build !e2e

package test

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

func init() {
	awsConfigFactory = func() (aws.Config, error) {
		return config.LoadDefaultConfig(context.Background(),
			config.WithRegion(TestRegion),
			config.WithCredentialsProvider(
				credentials.NewStaticCredentialsProvider("test", "test", "test"),
			),
		)
	}
	endpointOverride = LocalStackEndpoint
	usePathStyle = true
}
