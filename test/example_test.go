package test

// Example Terratest patterns for this template.
//
// When you add resources to tofu/, create a fixture in test/fixtures/
// and uncomment or adapt these patterns.
//
// --- Init and Plan ---
//
// func TestInitAndPlan(t *testing.T) {
// 	t.Parallel()
//
// 	uniqueID := strings.ToLower(random.UniqueId())
// 	namePrefix := fmt.Sprintf("test-%s", uniqueID)
//
// 	fixtureDir := test_structure.CopyTerraformFolderToTemp(t, "./fixtures", "default")
//
// 	terraformOptions := terraform.WithDefaultRetryableErrors(t, &terraform.Options{
// 		TerraformDir:    fixtureDir,
// 		TerraformBinary: "tofu",
// 		Vars: map[string]interface{}{
// 			"name_prefix": namePrefix,
// 		},
// 	})
//
// 	_, err := terraform.InitAndPlanE(t, terraformOptions)
// 	require.NoError(t, err, "tofu init/plan should succeed")
// }
//
// --- Apply and Destroy ---
//
// func TestApplyAndDestroy(t *testing.T) {
// 	t.Parallel()
//
// 	uniqueID := strings.ToLower(random.UniqueId())
// 	namePrefix := fmt.Sprintf("test-%s", uniqueID)
//
// 	fixtureDir := test_structure.CopyTerraformFolderToTemp(t, "./fixtures", "default")
//
// 	terraformOptions := terraform.WithDefaultRetryableErrors(t, &terraform.Options{
// 		TerraformDir:    fixtureDir,
// 		TerraformBinary: "tofu",
// 		Vars: map[string]interface{}{
// 			"name_prefix": namePrefix,
// 		},
// 	})
//
// 	t.Cleanup(func() { terraform.Destroy(t, terraformOptions) })
//
// 	terraform.InitAndApply(t, terraformOptions)
//
// 	// Validate outputs.
// 	// output := terraform.Output(t, terraformOptions, "name")
// 	// assert.Contains(t, output, namePrefix)
//
// 	// Validate AWS resources using the helpers.
// 	// cfg, err := getAWSConfig()
// 	// require.NoError(t, err)
// 	//
// 	// s3Client := newS3Client(&cfg)
// 	// waitForS3Bucket(t, s3Client, "my-bucket-name")
// }
