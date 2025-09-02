//go:build integration

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
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/uber-go/tally"
	"github.com/uber/kraken/core"
	"github.com/uber/kraken/lib/store"
	"github.com/uber/kraken/utils/dockerutil"
)

const (
	testImageForSigning = "alpine:latest"
	testRepo           = "test/signed-alpine"
	testTag            = "signed"
)

func TestImageVerificationIntegration(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "kraken-cosign-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	publicKeyPath := filepath.Join(tempDir, "cosign.pub")
	err = os.WriteFile(publicKeyPath, []byte("fake-public-key-for-testing"), 0644)
	require.NoError(t, err)

	td, cleanup := newTestDriver()
	defer cleanup()

	verificationFunc := CosignVerificationFunc(publicKeyPath)

	stats := tally.NewTestScope("", nil)

	sd := NewReadWriteStorageDriver(Config{}, td.cas, td.transferer, verificationFunc, stats)

	config := core.NewBlobFixture()
	layer1 := core.NewBlobFixture()
	layer2 := core.NewBlobFixture()

	manifestDigest, manifestRaw := dockerutil.ManifestFixture(config.Digest, layer1.Digest, layer2.Digest)

	for _, blob := range []*core.BlobFixture{config, layer1, layer2} {
		require.NoError(t, td.transferer.Upload("unused", blob.Digest, store.NewBufferFileReader(blob.Content)))
	}
	require.NoError(t, td.transferer.Upload("unused", manifestDigest, store.NewBufferFileReader(manifestRaw)))

	require.NoError(t, td.transferer.PutTag(fmt.Sprintf("%s:%s", testRepo, testTag), manifestDigest))

	path := genManifestTagCurrentLinkPath(testRepo, testTag, manifestDigest.Hex())
	
	t.Logf("Triggering verification by getting manifest...")
	data, err := sd.GetContent(contextFixture(), path)
	require.NoError(t, err)
	require.Greater(t, len(data), 0)

	time.Sleep(100 * time.Millisecond)

	snapshot := stats.Snapshot()
	
	successCounter := snapshot.Counters()["signature_verification_success+"]
	require.NotNil(t, successCounter, "signature_verification_success metric should be present")
	require.Equal(t, int64(1), successCounter.Value(), "signature_verification_success should be incremented")

	durationTimer := snapshot.Timers()["signature_verification_duration+"]
	require.NotNil(t, durationTimer, "signature_verification_duration metric should be present")
	require.Equal(t, 1, len(durationTimer.Values()), "signature_verification_duration should be recorded once")

	errorCounter := snapshot.Counters()["signature_verification_error+"]
	if errorCounter != nil {
		require.Equal(t, int64(0), errorCounter.Value(), "signature_verification_error should not be incremented")
	}

	failureCounter := snapshot.Counters()["signature_verification_failure+"]
	if failureCounter != nil {
		require.Equal(t, int64(0), failureCounter.Value(), "signature_verification_failure should not be incremented")
	}

	t.Logf("Integration test passed! Verification metrics recorded successfully.")
}

func TestImageVerificationIntegrationUnsignedImage(t *testing.T) {
	td, cleanup := newTestDriver()
	defer cleanup()

	verificationFunc := CosignVerificationFunc("/nonexistent/key.pub")

	stats := tally.NewTestScope("", nil)
	sd := NewReadWriteStorageDriver(Config{}, td.cas, td.transferer, verificationFunc, stats)

	config := core.NewBlobFixture()
	layer1 := core.NewBlobFixture()
	layer2 := core.NewBlobFixture()
	manifestDigest, manifestRaw := dockerutil.ManifestFixture(config.Digest, layer1.Digest, layer2.Digest)

	for _, blob := range []*core.BlobFixture{config, layer1, layer2} {
		require.NoError(t, td.transferer.Upload("unused", blob.Digest, store.NewBufferFileReader(blob.Content)))
	}
	require.NoError(t, td.transferer.Upload("unused", manifestDigest, store.NewBufferFileReader(manifestRaw)))
	require.NoError(t, td.transferer.PutTag("test/unsigned:latest", manifestDigest))

	path := genManifestTagCurrentLinkPath("test/unsigned", "latest", manifestDigest.Hex())
	_, err := sd.GetContent(contextFixture(), path)
	require.NoError(t, err) // Verification is advisory, doesn't block

	time.Sleep(100 * time.Millisecond)

	snapshot := stats.Snapshot()
	
	successCounter := snapshot.Counters()["signature_verification_success+"]
	if successCounter != nil {
		require.Equal(t, int64(0), successCounter.Value())
	}
}
