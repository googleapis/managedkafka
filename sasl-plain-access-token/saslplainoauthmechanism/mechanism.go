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
	"context"
	"fmt"

	"github.com/segmentio/kafka-go/sasl"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	cloudPlatformScope = "https://www.googleapis.com/auth/cloud-platform"
)

// sasl.Mechanism implementation that provides a valid Google Access Token
// for the SASL/Plain password
type Mechanism struct {
	emailAddress string
	tokenSource  oauth2.TokenSource
}

// Returns a Mechanism that uses Application Default Credentials as the Token Source
// and automatically determines the principal email address
func NewADCMechanism(ctx context.Context) (*Mechanism, error) {
	creds, err := google.FindDefaultCredentials(ctx, cloudPlatformScope)
	if err != nil {
		return nil, fmt.Errorf("error finding Application Default Credentials: %w", err)
	}
	email, err := getADCPrincipalEmail(creds)
	if err != nil {
		return nil, fmt.Errorf("error fetching principal email for Appication Default Credentials: %w", err)
	}
	return &Mechanism{
		emailAddress: email,
		tokenSource:  creds.TokenSource,
	}, nil
}

// Returns a mechanism that takes a custom TokenSource and static Principal Email
func NewMechanismWithTokenSource(ctx context.Context, ts oauth2.TokenSource, principalEmail string) (*Mechanism, error) {
	if err := validatePrincipalEmail(principalEmail); err != nil {
		return nil, fmt.Errorf("principalEmail did not pass validation: %w", err)
	}
	// Initial check that TokenSource returns a valid token
	_, err := ts.Token()
	if err != nil {
		return nil, fmt.Errorf("token source did not return a valid token: %w", err)
	}
	return &Mechanism{
		emailAddress: principalEmail,
		tokenSource:  ts,
	}, nil
}

func (*Mechanism) Name() string {
	return "PLAIN"
}

func (m *Mechanism) Start(ctx context.Context) (sasl.StateMachine, []byte, error) {
	token, err := m.tokenSource.Token()
	if err != nil {
		return nil, nil, fmt.Errorf("error generating token: %w", err)
	}
	return m, []byte(fmt.Sprintf("\x00%s\x00%s", m.emailAddress, token.AccessToken)), nil
}

func (m *Mechanism) Next(ctx context.Context, challenge []byte) (bool, []byte, error) {
	return true, nil, nil
}
