// Copyright 2026 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package bundle

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/sigstore/cosign/v3/internal/test"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	prototrustroot "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestLocalCertChainProvider_GetCertificateChain(t *testing.T) {
	rootCert, rootKey, err := test.GenerateRootCa()
	if err != nil {
		t.Fatalf("GenerateRootCa: %v", err)
	}
	subCert, subKey, err := test.GenerateSubordinateCa(rootCert, rootKey)
	if err != nil {
		t.Fatalf("GenerateSubordinateCa: %v", err)
	}
	leafCert, _, err := test.GenerateLeafCert("subject@mail.com", "oidc-issuer", subCert, subKey)
	if err != nil {
		t.Fatalf("GenerateLeafCert: %v", err)
	}

	leafPEM, err := cryptoutils.MarshalCertificateToPEM(leafCert)
	if err != nil {
		t.Fatalf("MarshalCertificateToPEM: %v", err)
	}
	rootPEM, err := cryptoutils.MarshalCertificateToPEM(rootCert)
	if err != nil {
		t.Fatalf("MarshalCertificateToPEM: %v", err)
	}
	subAndRootPEM, err := cryptoutils.MarshalCertificatesToPEM([]*x509.Certificate{subCert, rootCert})
	if err != nil {
		t.Fatalf("MarshalCertificatesToPEM: %v", err)
	}
	leafSubAndRootPEM, err := cryptoutils.MarshalCertificatesToPEM([]*x509.Certificate{leafCert, subCert, rootCert})
	if err != nil {
		t.Fatalf("MarshalCertificatesToPEM: %v", err)
	}

	testCases := []struct {
		name      string
		cert      []byte
		chain     []byte
		wantDER   [][]byte
		wantError bool
	}{
		{
			name:    "leaf with root-only chain drops the self-signed root",
			cert:    leafPEM,
			chain:   rootPEM,
			wantDER: [][]byte{leafCert.Raw},
		},
		{
			name:    "leaf with sub and root chain drops the self-signed root",
			cert:    leafPEM,
			chain:   subAndRootPEM,
			wantDER: [][]byte{leafCert.Raw, subCert.Raw},
		},
		{
			name:    "leaf already present in chain is deduped and root is dropped",
			cert:    leafPEM,
			chain:   leafSubAndRootPEM,
			wantDER: [][]byte{leafCert.Raw, subCert.Raw},
		},
		{
			name:      "invalid leaf PEM",
			cert:      []byte("not a pem"),
			chain:     rootPEM,
			wantError: true,
		},
		{
			name:      "invalid chain PEM",
			cert:      leafPEM,
			chain:     []byte("not a pem"),
			wantError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider := &localCertChainProvider{cert: tc.cert, chain: tc.chain}
			got, err := provider.GetCertificateChain(context.Background(), nil, nil)
			if tc.wantError {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tc.wantDER) {
				t.Fatalf("expected %d certs, got %d", len(tc.wantDER), len(got))
			}
			for i := range got {
				if !bytes.Equal(got[i], tc.wantDER[i]) {
					t.Errorf("cert at index %d does not match expected DER", i)
				}
			}
		})
	}
}

type ctxKey struct{}

// recordingTransport records the ctxKey context value of each request, then
// sends it with http.DefaultTransport.
type recordingTransport struct {
	mu     sync.Mutex
	values []any
}

func (r *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	r.values = append(r.values, req.Context().Value(ctxKey{}))
	r.mu.Unlock()
	return http.DefaultTransport.RoundTrip(req)
}

func (r *recordingTransport) recorded() []any {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.values
}

func TestSignDataTransportsAndContext(t *testing.T) {
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}

	// The stand-in Fulcio certifies the requested public key, as Rekor v1
	// entry creation checks the signature against the certificate.
	rootCert, rootKey, err := test.GenerateRootCa()
	if err != nil {
		t.Fatal(err)
	}
	fulcioSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			PublicKeyRequest struct {
				PublicKey struct {
					Content string `json:"content"`
				} `json:"publicKey"`
			} `json:"publicKeyRequest"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		pub, err := cryptoutils.UnmarshalPEMToPublicKey([]byte(req.PublicKeyRequest.PublicKey.Content))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		template := &x509.Certificate{
			SerialNumber:   big.NewInt(1),
			EmailAddresses: []string{"subject@mail.com"},
			NotBefore:      time.Now().Add(-time.Minute),
			NotAfter:       time.Now().Add(10 * time.Minute),
			KeyUsage:       x509.KeyUsageDigitalSignature,
			ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		}
		der, err := x509.CreateCertificate(rand.Reader, template, rootCert, pub, rootKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
		_ = json.NewEncoder(w).Encode(map[string]any{
			"signedCertificateEmbeddedSct": map[string]any{"chain": map[string]any{"certificates": []string{certPEM}}},
		})
	}))
	defer fulcioSrv.Close()

	tsaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		resp, err := vs.TimestampResponse(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(resp)
	}))
	defer tsaSrv.Close()

	rekorV1Srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		entity, err := vs.Attest("subject@mail.com", "oidc-issuer", []byte(`{}`))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		entries, err := entity.TlogEntries()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		tle := entries[0].TransparencyLogEntry()
		logID := hex.EncodeToString(tle.GetLogId().GetKeyId())
		rootHash := "deadbeef"
		treeSize := int64(1)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", "entry")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]models.LogEntryAnon{
			"entry": {
				Body:           base64.StdEncoding.EncodeToString(tle.GetCanonicalizedBody()),
				IntegratedTime: &tle.IntegratedTime,
				LogID:          &logID,
				LogIndex:       &tle.LogIndex,
				Verification: &models.LogEntryAnonVerification{
					InclusionProof: &models.InclusionProof{
						Checkpoint: &rootHash,
						Hashes:     []string{},
						LogIndex:   &tle.LogIndex,
						RootHash:   &rootHash,
						TreeSize:   &treeSize,
					},
				},
			},
		})
	}))
	defer rekorV1Srv.Close()

	rekorV2Srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		body, err := protojson.Marshal(&protorekor.TransparencyLogEntry{LogIndex: 1})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(body)
	}))
	defer rekorV2Srv.Close()

	enc := base64.RawURLEncoding.EncodeToString
	idToken := enc([]byte(`{"alg":"none"}`)) + "." + enc([]byte(`{"sub":"subject@mail.com","iss":"oidc-issuer"}`)) + ".sig"
	ctx := context.WithValue(context.Background(), ctxKey{}, "caller")
	content := &sign.PlainData{Data: []byte("hello world")}

	start := time.Now().Add(-time.Hour)
	svc := func(url string, version uint32) []root.Service {
		return []root.Service{{URL: url, MajorAPIVersion: version, ValidityPeriodStart: start}}
	}
	anyOne := root.ServiceConfiguration{Selector: prototrustroot.ServiceSelector_ANY}

	for _, tc := range []struct {
		name         string
		rekorURL     string
		rekorVersion uint32
	}{
		{"rekor v1", rekorV1Srv.URL, 1},
		{"rekor v2", rekorV2Srv.URL, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			signingConfig, err := root.NewSigningConfig(root.SigningConfigMediaType02,
				svc(fulcioSrv.URL, 1), nil,
				svc(tc.rekorURL, tc.rekorVersion), anyOne,
				svc(tsaSrv.URL+"/api/v1/timestamp", 1), anyOne)
			if err != nil {
				t.Fatal(err)
			}
			keypair, err := sign.NewEphemeralKeypair(nil)
			if err != nil {
				t.Fatal(err)
			}
			fulcioTransport := &recordingTransport{}
			tsaTransport := &recordingTransport{}
			rekorTransport := &recordingTransport{}

			// The trusted material is nil, so the stand-in services'
			// responses are not verified.
			_, err = SignData(ctx, content, keypair, idToken, nil, nil, signingConfig, nil, SignOptions{
				FulcioClientTransport: fulcioTransport,
				TSAClientTransport:    tsaTransport,
				RekorClientTransport:  rekorTransport,
			})
			if err != nil {
				t.Fatalf("SignData: %v", err)
			}

			for name, rt := range map[string]*recordingTransport{
				"fulcio": fulcioTransport,
				"tsa":    tsaTransport,
				"rekor":  rekorTransport,
			} {
				got := rt.recorded()
				if len(got) != 1 || got[0] != "caller" {
					t.Errorf("%s transport saw context values %v, want one request with %q", name, got, "caller")
				}
			}
		})
	}
}
