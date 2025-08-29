// Copyright (c) 2016-2025 Uber Technologies, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package dockerregistry

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/uber-go/tally"
	"github.com/uber/kraken/core"
	"github.com/uber/kraken/lib/store"
	"github.com/uber/kraken/utils/dockerutil"
)

const (
	cosignTestPassword = "testpassword"
	cosignTestKeyDir   = "/tmp/cosign-test-keys"
)

func runCosign(args ...string) error {
	stderr := new(bytes.Buffer)
	cmd := exec.Command("cosign", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("exec `%s`: %s, stderr:\n%s",
			strings.Join(cmd.Args, " "), err, stderr.String())
	}
	return nil
}

func runCosignWithOutput(args ...string) ([]byte, error) {
	stderr := new(bytes.Buffer)
	stdout := new(bytes.Buffer)
	cmd := exec.Command("cosign", args...)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("exec `%s`: %s, stderr:\n%s",
			strings.Join(cmd.Args, " "), err, stderr.String())
	}
	return stdout.Bytes(), nil
}

func setupCosignKeys(t *testing.T) (string, string) {
	t.Helper()

	testDir := t.TempDir()
	privateKeyPath := filepath.Join(testDir, "test.key")
	publicKeyPath := filepath.Join(testDir, "test.pub")

	sourcePrivateKey := filepath.Join(cosignTestKeyDir, "test.key")
	sourcePublicKey := filepath.Join(cosignTestKeyDir, "test.pub")

	privateKeyData, err := os.ReadFile(sourcePrivateKey)
	require.NoError(t, err, "failed to read source private key")

	publicKeyData, err := os.ReadFile(sourcePublicKey)
	require.NoError(t, err, "failed to read source public key")

	err = os.WriteFile(privateKeyPath, privateKeyData, 0600)
	require.NoError(t, err, "failed to write private key")

	err = os.WriteFile(publicKeyPath, publicKeyData, 0644)
	require.NoError(t, err, "failed to write public key")

	return privateKeyPath, publicKeyPath
}

func signManifestBlob(t *testing.T, manifestData []byte, privateKeyPath string) []byte {
	t.Helper()

	tempFile, err := os.CreateTemp("", "manifest-*.json")
	require.NoError(t, err)
	defer os.Remove(tempFile.Name())

	_, err = tempFile.Write(manifestData)
	require.NoError(t, err)
	tempFile.Close()

	sigFile := tempFile.Name() + ".sig"
	defer os.Remove(sigFile)

	cmd := exec.Command("cosign", "sign-blob", "--key", privateKeyPath, "--output-signature", sigFile, "--tlog-upload=false", "--yes", tempFile.Name())
	cmd.Env = append(os.Environ(), 
		"COSIGN_PASSWORD="+cosignTestPassword,
		"SIGSTORE_NO_DEFAULT_TUF_ROOT=1",
	)
	
	stderr := new(bytes.Buffer)
	cmd.Stderr = stderr
	err = cmd.Run()
	require.NoError(t, err, "failed to sign manifest blob: %s", stderr.String())

	sigData, err := os.ReadFile(sigFile)
	require.NoError(t, err, "failed to read signature file")

	return sigData
}

func cosignVerifier(publicKeyPath string) func(repo string, digest core.Digest, blob store.FileReader) (SignatureVerificationDecision, error) {
	return func(repo string, digest core.Digest, blob store.FileReader) (SignatureVerificationDecision, error) {
		manifestData, err := io.ReadAll(blob)
		if err != nil {
			return DecisionSkip, fmt.Errorf("failed to read manifest data: %w", err)
		}

		tempFile, err := os.CreateTemp("", "manifest-verify-*.json")
		if err != nil {
			return DecisionSkip, fmt.Errorf("failed to create temp file: %w", err)
		}
		defer os.Remove(tempFile.Name())

		_, err = tempFile.Write(manifestData)
		if err != nil {
			return DecisionSkip, fmt.Errorf("failed to write manifest to temp file: %w", err)
		}
		tempFile.Close()

		sigFile := tempFile.Name() + ".sig"
		defer os.Remove(sigFile)

		if _, err := os.Stat(sigFile); os.IsNotExist(err) {
			return DecisionSkip, nil
		}

		cmd := exec.Command("cosign", "verify-blob", "--key", publicKeyPath, "--signature", sigFile, tempFile.Name())
		stderr := new(bytes.Buffer)
		cmd.Stderr = stderr
		
		if err := cmd.Run(); err != nil {
			if strings.Contains(stderr.String(), "no matching signatures") || 
			   strings.Contains(stderr.String(), "signature not found") {
				return DecisionSkip, nil
			}
			return DecisionDeny, nil
		}

		return DecisionAllow, nil
	}
}

func buildDriverWithCosignVerification(t *testing.T, manifestData []byte, signature []byte, publicKeyPath string, called *bool) (*KrakenStorageDriver, string, string) {
	t.Helper()

	td, cleanup := newTestDriver()
	t.Cleanup(cleanup)

	config := core.NewBlobFixture()
	layer1 := core.NewBlobFixture()
	layer2 := core.NewBlobFixture()

	var manifestDigest core.Digest
	var manifestRaw []byte
	
	if manifestData != nil {
		manifestRaw = manifestData
		var err error
		manifestDigest, err = core.NewDigester().FromBytes(manifestRaw)
		require.NoError(t, err)
	} else {
		manifestDigest, manifestRaw = dockerutil.ManifestFixture(config.Digest, layer1.Digest, layer2.Digest)
	}

	for _, blob := range []*core.BlobFixture{config, layer1, layer2} {
		require.NoError(t, td.transferer.Upload("unused", blob.Digest, store.NewBufferFileReader(blob.Content)))
	}
	require.NoError(t, td.transferer.Upload("unused", manifestDigest, store.NewBufferFileReader(manifestRaw)))

	repo := repoName
	tag := tagName
	require.NoError(t, td.transferer.PutTag(fmt.Sprintf("%s:%s", repo, tag), manifestDigest))

	if signature != nil {
		sigFile := fmt.Sprintf("/tmp/manifest-%s.sig", manifestDigest.Hex())
		err := os.WriteFile(sigFile, signature, 0644)
		require.NoError(t, err)
		t.Cleanup(func() { os.Remove(sigFile) })
	}

	verif := func(vRepo string, vDigest core.Digest, blob store.FileReader) (SignatureVerificationDecision, error) {
		if called != nil {
			*called = true
		}
		require.Equal(t, repo, vRepo)
		require.Equal(t, manifestDigest, vDigest)


		manifestData, err := io.ReadAll(blob)
		if err != nil {
			return DecisionSkip, fmt.Errorf("failed to read manifest data: %w", err)
		}

		tempFile, err := os.CreateTemp("", "manifest-verify-*.json")
		if err != nil {
			return DecisionSkip, fmt.Errorf("failed to create temp file: %w", err)
		}
		defer os.Remove(tempFile.Name())

		_, err = tempFile.Write(manifestData)
		if err != nil {
			return DecisionSkip, fmt.Errorf("failed to write manifest to temp file: %w", err)
		}
		tempFile.Close()

		sigFile := fmt.Sprintf("/tmp/manifest-%s.sig", vDigest.Hex())
		if _, err := os.Stat(sigFile); os.IsNotExist(err) {
			return DecisionSkip, nil
		}

		cmd := exec.Command("cosign", "verify-blob", "--key", publicKeyPath, "--signature", sigFile, "--insecure-ignore-tlog", tempFile.Name())
		cmd.Env = append(os.Environ(), "SIGSTORE_NO_DEFAULT_TUF_ROOT=1")
		stderr := new(bytes.Buffer)
		stdout := new(bytes.Buffer)
		cmd.Stderr = stderr
		cmd.Stdout = stdout
		
		if err := cmd.Run(); err != nil {
			return DecisionDeny, nil
		}
		return DecisionAllow, nil
	}

	stats := tally.NewTestScope("", nil)
	sd := NewReadWriteStorageDriver(Config{}, td.cas, td.transferer, verif, stats)

	path := genManifestTagCurrentLinkPath(repo, tag, manifestDigest.Hex())
	return sd, path, ""
}

func TestCosignVerification_ValidSignature(t *testing.T) {
	privateKeyPath, publicKeyPath := setupCosignKeys(t)

	config := core.NewBlobFixture()
	layer1 := core.NewBlobFixture()
	layer2 := core.NewBlobFixture()

	_, manifestData := dockerutil.ManifestFixture(config.Digest, layer1.Digest, layer2.Digest)
	signature := signManifestBlob(t, manifestData, privateKeyPath)

	var called bool
	sd, path, _ := buildDriverWithCosignVerification(t, manifestData, signature, publicKeyPath, &called)

	data, err := sd.GetContent(contextFixture(), path)
	require.NoError(t, err)
	require.Greater(t, len(data), 0)
	require.True(t, called, "verification should be called")

	stats, ok := sd.metrics.(tally.TestScope)
	require.True(t, ok, "metrics should be a TestScope")
	snapshot := stats.Snapshot()
	
	successCounterKey := signatureVerificationSuccessCounter + "+"
	successCounter, exists := snapshot.Counters()[successCounterKey]
	require.True(t, exists, "success counter should exist")
	require.Equal(t, int64(1), successCounter.Value())
}

func TestCosignVerification_UnsignedImage(t *testing.T) {
	_, publicKeyPath := setupCosignKeys(t)

	var called bool
	sd, path, _ := buildDriverWithCosignVerification(t, nil, nil, publicKeyPath, &called)

	data, err := sd.GetContent(contextFixture(), path)
	require.NoError(t, err)
	require.Greater(t, len(data), 0)
	require.True(t, called, "verification should be called")
}

func TestCosignVerification_InvalidSignature(t *testing.T) {
	privateKeyPath, publicKeyPath := setupCosignKeys(t)

	config := core.NewBlobFixture()
	layer1 := core.NewBlobFixture()
	layer2 := core.NewBlobFixture()

	_, manifestData := dockerutil.ManifestFixture(config.Digest, layer1.Digest, layer2.Digest)
	
	validSignature := signManifestBlob(t, manifestData, privateKeyPath)
	
	invalidSignature := make([]byte, len(validSignature))
	copy(invalidSignature, validSignature)
	invalidSignature[0] = invalidSignature[0] ^ 0xFF

	var called bool
	sd, path, _ := buildDriverWithCosignVerification(t, manifestData, invalidSignature, publicKeyPath, &called)

	data, err := sd.GetContent(contextFixture(), path)
	require.NoError(t, err)
	require.Greater(t, len(data), 0)
	require.True(t, called, "verification should be called")

	stats, ok := sd.metrics.(tally.TestScope)
	require.True(t, ok, "metrics should be a TestScope")
	snapshot := stats.Snapshot()
	
	failureCounterKey := signatureVerificationFailureCounter + "+"
	failureCounter, exists := snapshot.Counters()[failureCounterKey]
	require.True(t, exists, "failure counter should exist")
	require.Equal(t, int64(1), failureCounter.Value())
}
