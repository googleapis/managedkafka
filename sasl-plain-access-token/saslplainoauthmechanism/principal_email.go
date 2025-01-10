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
	"io"
	"net/http"
	"net/mail"
	"regexp"
	"strings"

	"cloud.google.com/go/compute/metadata"
	"golang.org/x/oauth2/google"
)

const (
	// API URL for looking up additional information on an Access Token
	tokenInfoAPIURL = "https://www.googleapis.com/oauth2/v3/tokeninfo/?access_token="
	// Metadatadata Server name for the default Service Account
	defaultServiceAccountMetadataServerName = "default"
)

// Returns the principal email address for ADC credentials
func getADCPrincipalEmail(creds *google.Credentials) (string, error) {

	// If we are in GCE - then we can fetch the email address of the default Service Account
	// directly from the Metadata server
	if metadata.OnGCE() {
		email, err := metadata.Email(defaultServiceAccountMetadataServerName)
		if err != nil {
			return "", fmt.Errorf("detected GCE, but unable to get Service Account email for default: %w", err)
		}
		if validatePrincipalEmail(email) != nil {
			return "", err
		}
		return email, nil
	}

	// If we are not running in an environment with a Metadata Server, we need to use the Service Account
	// JSON to fetch the principal email
	if creds.JSON != nil {
		return principalEmailFromJSON(creds)
	}

	return "", errors.New("unable to determine principal email, did not detect Metadata Server or JSON Credentials")
}

// Checks that the Service Account in use is a Google Service Account, and not an unsupported type
func validatePrincipalEmail(email string) error {
	// TODO: Relax principal:// restriction once b/385138184 is resolved.
	// There are two responses that the Metadata server will return for http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email in GKE
	// If the KSA is **not** annotated with 'iam.gke.io/return-principal-id-as-email: "true"', then it will return the Workload Identity Pool name
	// If it **is** annotated with 'iam.gke.io/return-principal-id-as-email: "true"' then it will return the full principal identifier
	if strings.HasSuffix(email, ".svc.id.goog") || strings.HasPrefix(email, "principal://iam.googleapis.com") {
		return errors.New("GMK SASL PLAIN OAuth cannot be used with direct Workload Identity Federation - you must configure KSA --> GSA impersonation, see: https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity#kubernetes-sa-to-iam")
	}
	_, err := mail.ParseAddress(email)
	if err != nil {
		return fmt.Errorf("invalid email address '%s': %w", email, err)
	}
	return nil
}

// Fetches the principal email from JSON credentials
func principalEmailFromJSON(creds *google.Credentials) (string, error) {
	token := struct {
		Type                           string `json:"type"`
		ServiceAccountImpersonationURL string `json:"service_account_impersonation_url"`
	}{}
	if err := json.Unmarshal(creds.JSON, &token); err != nil {
		return "", fmt.Errorf("error decoding token JSON: %w", err)
	}
	switch token.Type {
	case "impersonated_service_account":
		return emailFromImpersonationURL(token.ServiceAccountImpersonationURL)
	case "authorized_user":
		return getPrincipalEmailFromTokenEndpoint(creds, *http.DefaultClient, tokenInfoAPIURL)
	case "":
		return "", errors.New("no token type detected in ADC JSON")
	default:
		return "", fmt.Errorf("unsupported JSON token type: '%s'", token.Type)
	}
}

// Extracts a Service Account email from an impersonation URL, for example
// https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/gmk@my-project.iam.gserviceaccount.com:generateAccessToken
// returns gmk@my-project.iam.gserviceaccount.com
func emailFromImpersonationURL(url string) (string, error) {
	re, err := regexp.Compile(`[a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9_-]+`)
	if err != nil {
		return "", fmt.Errorf("unable to extract email from impersonation URL, bad regex compile: %w", err)
	}
	match := re.FindString(url)
	if match == "" {
		return "", fmt.Errorf("unable to extract email from impersonation URL: %s", url)
	}
	return match, nil
}

// Sends the token to the tokenInfoAPIURL endpoint, and extracts the "email" field from the response
func getPrincipalEmailFromTokenEndpoint(creds *google.Credentials, c http.Client, tokenInfoAPIURL string) (string, error) {
	token, err := creds.TokenSource.Token()
	if err != nil {
		return "", fmt.Errorf("error fetching Access Token for principal email lookup: %w", err)
	}
	resp, err := c.Get(tokenInfoAPIURL + token.AccessToken)
	if err != nil {
		return "", err
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response body: %w", err)
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("got %v response code: %s", resp.StatusCode, data)
	}

	email := struct {
		Email string `json:"email"`
	}{}
	err = json.Unmarshal(data, &email)
	if err != nil {
		return "", fmt.Errorf("error unmarshalling token info response: %w", err)
	}
	if email.Email == "" {
		return "", errors.New("got empty email in response")
	}
	return email.Email, err

}
