// Copyright 2021 Gravitational, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package webauthn

import (
	"github.com/duo-labs/webauthn/protocol"

	wantypes "github.com/gravitational/teleport/api/types/webauthn"
)

// CredentialAssertionToProto converts a CredentialAssertion to its proto
// counterpart.
func CredentialAssertionToProto(assertion *CredentialAssertion) *wantypes.CredentialAssertion {
	return &wantypes.CredentialAssertion{
		PublicKey: &wantypes.PublicKeyCredentialRequestOptions{
			Challenge:        assertion.Response.Challenge,
			TimeoutMs:        int64(assertion.Response.Timeout),
			RpId:             assertion.Response.RelyingPartyID,
			AllowCredentials: credentialDescriptorsToProto(assertion.Response.AllowedCredentials),
			Extensions:       inputExtensionsToProto(assertion.Response.Extensions),
		},
	}
}

// CredentialAssertionFromProto converts a CredentialAssertion proto to its lib
// counterpart.
func CredentialAssertionFromProto(assertion *wantypes.CredentialAssertion) *CredentialAssertion {
	return &CredentialAssertion{
		Response: protocol.PublicKeyCredentialRequestOptions{
			Challenge:          assertion.PublicKey.Challenge,
			Timeout:            int(assertion.PublicKey.TimeoutMs),
			RelyingPartyID:     assertion.PublicKey.RpId,
			AllowedCredentials: credentialDescriptorsFromProto(assertion.PublicKey.AllowCredentials),
			Extensions:         inputExtensionsFromProto(assertion.PublicKey.Extensions),
		},
	}
}

func credentialDescriptorsToProto(creds []protocol.CredentialDescriptor) []*wantypes.CredentialDescriptor {
	res := make([]*wantypes.CredentialDescriptor, len(creds))
	for i, cred := range creds {
		res[i] = &wantypes.CredentialDescriptor{
			Type: string(cred.Type),
			Id:   cred.CredentialID,
		}
	}
	return res
}

func inputExtensionsToProto(exts protocol.AuthenticationExtensions) *wantypes.AuthenticationExtensionsClientInputs {
	if len(exts) == 0 {
		return nil
	}
	res := &wantypes.AuthenticationExtensionsClientInputs{}
	if value, ok := exts[AppIDExtension]; ok {
		// Type should always be string, since we are the ones setting it, but let's
		// play it safe and check anyway.
		if appID, ok := value.(string); ok {
			res.AppId = appID
		}
	}
	return res
}

func credentialDescriptorsFromProto(creds []*wantypes.CredentialDescriptor) []protocol.CredentialDescriptor {
	res := make([]protocol.CredentialDescriptor, len(creds))
	for i, cred := range creds {
		res[i] = protocol.CredentialDescriptor{
			Type:         protocol.CredentialType(cred.Type),
			CredentialID: cred.Id,
		}
	}
	return res
}

func inputExtensionsFromProto(exts *wantypes.AuthenticationExtensionsClientInputs) protocol.AuthenticationExtensions {
	if exts == nil {
		return nil
	}
	res := make(map[string]interface{})
	if exts.AppId != "" {
		res[AppIDExtension] = exts.AppId
	}
	return res
}
