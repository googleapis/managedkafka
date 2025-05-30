/*
 Copyright 2025 Google LLC

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

      https://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
*/

package saslplainoauthmechanism

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

func TestValidatePrincipalEmail(t *testing.T) {

	tests := []struct {
		name      string
		email     string
		expectErr bool
	}{
		{
			name:      "GSA Email - Valid",
			email:     "my-sa@my-project.iam.gserviceaccount.com",
			expectErr: false,
		},
		{
			name:      "User Email - Valid",
			email:     "human-principal@example.com",
			expectErr: false,
		},
		{
			name:      "GKE WIF Principal - Valid",
			email:     "principal://iam.googleapis.com/projects/1234567891011/locations/global/workloadIdentityPools/my-project.svc.id.goog/subject/ns/custom-namespace/sa/gmktest",
			expectErr: false,
		},
		{
			name:      "Standard Workload Identity Principal - Valid",
			email:     "principal://iam.googleapis.com/projects/12345678/locations/global/workloadIdentityPools/my-pool/subject/my-subject",
			expectErr: false,
		},
		{
			name:      "Standard Workforce Identity Principal - Valid",
			email:     "principal://iam.googleapis.com/locations/global/workforcePools/altostrat-contractors/subject/raha@altostrat.com",
			expectErr: false,
		},

		{
			name:      "Empty email - Invalid",
			email:     "",
			expectErr: true,
		},
		{
			name:      "Non RFC Email - Invalid",
			email:     "human[]principaluser@example.com",
			expectErr: true,
		},
		{
			name:      "Bad  WIF Principal Bad Prefix - Invalid",
			email:     "principal://iammmmmmmm.googleapis.com/projects/1234567891011/locations/global/workloadIdentityPools/my-project.svc.id.goog/subject/ns/custom-namespace/sa/gmktest",
			expectErr: true,
		},
		{
			name:      "Workload Identity Federation Pool - No iam.gke.io/return-principal-id-as-email KSA annotation - Invalid",
			email:     "my-project.svc.id.goog",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePrincipalEmail(tt.email)
			if tt.expectErr {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
			}
		})
	}

}

func TestEmailFromImpersonationURL(t *testing.T) {

	var tests = []struct {
		name      string
		input     string
		want      string
		expectErr bool
	}{
		{
			name:      "Valid email 1",
			input:     "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/gmk@project.iam.gserviceaccount.com:generateAccessToken",
			want:      "gmk@project.iam.gserviceaccount.com",
			expectErr: false,
		},
		{
			name:      "Valid email 2 - Hyphens",
			input:     "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/gmk-with-hyphens@my-project-2.iam.gserviceaccount.com:generateAccessToken",
			want:      "gmk-with-hyphens@my-project-2.iam.gserviceaccount.com",
			expectErr: false,
		},
		{
			name:      "Valid email 3",
			input:     "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/gmk@projectiam.iam.gserviceaccount.com:generateAccessToken",
			want:      "gmk@projectiam.iam.gserviceaccount.com",
			expectErr: false,
		},
		{
			name:      "Bad format",
			input:     "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/gmk-with-hyphens@:generateAccessToken",
			want:      "",
			expectErr: true,
		},
		{
			name:      "No email",
			input:     "https://google.com/no-email-here",
			want:      "",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := emailFromImpersonationURL(tt.input)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}

}

func TestGetPrincipalEmailFromTokenEndpoint(t *testing.T) {

	var tests = []struct {
		name         string
		statusCode   int
		responseBody map[string]interface{}
		tsToken      *oauth2.Token
		tsErr        error
		expectErr    bool
		expectEmail  string
	}{
		{
			name:       "Valid Token Response",
			statusCode: http.StatusOK,
			responseBody: map[string]interface{}{
				"email": "test@example.com",
			},
			tsToken:     &oauth2.Token{AccessToken: "abc"},
			tsErr:       nil,
			expectErr:   false,
			expectEmail: "test@example.com",
		},
		{
			name:       "Server Errror",
			statusCode: http.StatusInternalServerError,
			responseBody: map[string]interface{}{
				"error": "Something went wrong",
			},
			tsToken:     &oauth2.Token{AccessToken: "abc"},
			tsErr:       nil,
			expectErr:   true,
			expectEmail: "",
		},
		{
			name:       "No email in token response",
			statusCode: http.StatusOK,
			responseBody: map[string]interface{}{
				"expires_in": 12345,
			},
			tsToken:     &oauth2.Token{AccessToken: "abc"},
			tsErr:       nil,
			expectErr:   true,
			expectEmail: "",
		},
		{
			name:       "Issue fetching token",
			statusCode: http.StatusOK,
			responseBody: map[string]interface{}{
				"email": "test@example.com",
			},
			tsToken:     nil,
			tsErr:       errors.New("Token error"),
			expectErr:   true,
			expectEmail: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				body, err := json.Marshal(tt.responseBody)
				if err != nil {
					t.Fatalf("error marshalling response body to JSON: %v", err)
				}

				fmt.Fprintf(w, "%s", body)
			}))
			defer ts.Close()

			mockTokenSource := new(mockTokenSource)
			mockTokenSource.On("Token").Return(tt.tsToken, tt.tsErr)

			token, err := getPrincipalEmailFromTokenEndpoint(&google.Credentials{
				TokenSource: mockTokenSource,
			}, *http.DefaultClient, ts.URL+"/")

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectEmail, token)
				mockTokenSource.AssertCalled(t, "Token")
			}

		})
	}
}
