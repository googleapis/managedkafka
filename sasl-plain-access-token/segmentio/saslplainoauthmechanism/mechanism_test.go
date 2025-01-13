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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/oauth2"
)

// mockTokenSource implements the oauth2.TokenSource interface
type mockTokenSource struct {
	mock.Mock
}

// Token implements the Token method on mockTokenSource to satisfy the
// oauth2.TokenSource interface
func (m *mockTokenSource) Token() (*oauth2.Token, error) {
	args := m.Called()
	return args.Get(0).(*oauth2.Token), args.Error(1)
}

func TestNewMechanismWithTokenSource(t *testing.T) {
	tests := []struct {
		name           string
		tsToken        *oauth2.Token // The Token to be returned by the TokenSource
		tsErr          error         // The error to be returned by the TokenSource
		principalEmail string
		expectErr      bool
	}{
		{
			name:           "Valid Token and Email",
			tsToken:        &oauth2.Token{AccessToken: "abc12134"},
			tsErr:          nil,
			principalEmail: "test@example.com",
			expectErr:      false,
		},
		{
			name:           "Valid Token, Bad Email",
			tsToken:        &oauth2.Token{AccessToken: "abc12134"},
			tsErr:          nil,
			principalEmail: "this-is-not-an-email",
			expectErr:      true,
		},
		{
			name:           "Token Error",
			tsToken:        nil,
			tsErr:          errors.New("some error generating token"),
			principalEmail: "test@example.com",
			expectErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			mockTokenSource := new(mockTokenSource)
			mockTokenSource.On("Token").Return(tt.tsToken, tt.tsErr)

			mechanism, err := NewMechanismWithTokenSource(context.Background(), mockTokenSource, tt.principalEmail)

			if !tt.expectErr {
				mockTokenSource.AssertCalled(t, "Token")
				assert.NoError(t, err)
				assert.Equal(t, tt.principalEmail, mechanism.emailAddress)
				assert.Equal(t, mockTokenSource, mechanism.tokenSource)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestMechanism_Name(t *testing.T) {
	m := Mechanism{}
	assert.Equal(t, "PLAIN", m.Name())
}

func TestMechanism_Start(t *testing.T) {

	tests := []struct {
		name           string
		tsToken        *oauth2.Token
		principalEmail string
		expectedOutput string
	}{
		{
			name:           "Valid Token and Email",
			tsToken:        &oauth2.Token{AccessToken: "abc12134"},
			principalEmail: "test@example.com",
			expectedOutput: "\x00test@example.com\x00abc12134",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockTokenSource := new(mockTokenSource)
			mockTokenSource.On("Token").Return(tt.tsToken, nil)

			mechanism := &Mechanism{tt.principalEmail, mockTokenSource}
			stateMachine, output, err := mechanism.Start(context.Background())

			assert.NoError(t, err)
			assert.Equal(t, tt.expectedOutput, string(output))
			assert.NotNil(t, stateMachine)

		})
	}
}
