/**
 * Copyright 2021 Gravitational, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package auth

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/constants"
	"github.com/gravitational/teleport/api/types"
	apievents "github.com/gravitational/teleport/api/types/events"
	"github.com/gravitational/teleport/lib/auth/mocku2f"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/modules"
	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"github.com/pquerna/otp/totp"
	"github.com/tstranex/u2f"

	"github.com/stretchr/testify/require"
)

type testWithCloudModules struct {
	modules.Modules
}

func (m *testWithCloudModules) Features() modules.Features {
	return modules.Features{
		Cloud: true, // Enable cloud feature which is required for account recovery.
	}
}

// TestGenerateAndUpsertRecoveryCodes tests the following:
//  - generation of recovery codes are of correct format
//  - recovery codes are upserted
//  - recovery codes can be verified and marked used
//  - reusing a used or non-existing token returns error
func TestGenerateAndUpsertRecoveryCodes(t *testing.T) {
	t.Parallel()
	srv := newTestTLSServer(t)
	ctx := context.Background()

	user := "fake@fake.com"
	rc, err := srv.Auth().generateAndUpsertRecoveryCodes(ctx, user)
	require.NoError(t, err)
	require.Len(t, rc, 3)

	// Test codes are not marked used.
	recovery, err := srv.Auth().GetRecoveryCodes(ctx, user)
	require.NoError(t, err)
	for _, token := range recovery.GetCodes() {
		require.False(t, token.IsUsed)
	}

	// Test each codes are of correct format and used.
	for _, code := range rc {
		s := strings.Split(code, "-")

		// 9 b/c 1 for prefix, 8 for words.
		require.Len(t, s, 9)
		require.True(t, strings.HasPrefix(code, "tele-"))

		// Test codes match.
		err := srv.Auth().verifyRecoveryCode(ctx, user, []byte(code))
		require.NoError(t, err)
	}

	// Test used codes are marked used.
	recovery, err = srv.Auth().GetRecoveryCodes(ctx, user)
	require.NoError(t, err)
	for _, token := range recovery.GetCodes() {
		require.True(t, token.IsUsed)
	}

	// Test with a used code returns error.
	err = srv.Auth().verifyRecoveryCode(ctx, user, []byte(rc[0]))
	require.True(t, trace.IsBadParameter(err))

	// Test with invalid recovery code returns error.
	err = srv.Auth().verifyRecoveryCode(ctx, user, []byte("invalidcode"))
	require.True(t, trace.IsBadParameter(err))

	// Test with non-existing user returns error.
	err = srv.Auth().verifyRecoveryCode(ctx, "doesnotexist", []byte(rc[0]))
	require.True(t, trace.IsBadParameter(err))
}

func TestRecoveryCodeEventsEmitted(t *testing.T) {
	t.Parallel()
	srv := newTestTLSServer(t)
	ctx := context.Background()
	mockEmitter := &events.MockEmitter{}
	srv.Auth().emitter = mockEmitter

	user := "fake@fake.com"

	// Test generated recovery codes event.
	tc, err := srv.Auth().generateAndUpsertRecoveryCodes(ctx, user)
	require.NoError(t, err)
	event := mockEmitter.LastEvent()
	require.Equal(t, events.RecoveryCodeGeneratedEvent, event.GetType())
	require.Equal(t, events.RecoveryCodesGenerateCode, event.GetCode())

	// Test used recovery code event.
	err = srv.Auth().verifyRecoveryCode(ctx, user, []byte(tc[0]))
	require.NoError(t, err)
	event = mockEmitter.LastEvent()
	require.Equal(t, events.RecoveryCodeUsedEvent, event.GetType())
	require.Equal(t, events.RecoveryCodeUseSuccessCode, event.GetCode())

	// Re-using the same token emits failed event.
	err = srv.Auth().verifyRecoveryCode(ctx, user, []byte(tc[0]))
	require.Error(t, err)
	event = mockEmitter.LastEvent()
	require.Equal(t, events.RecoveryCodeUsedEvent, event.GetType())
	require.Equal(t, events.RecoveryCodeUseFailureCode, event.GetCode())
}

func TestStartAccountRecovery(t *testing.T) {
	srv := newTestTLSServer(t)
	ctx := context.Background()
	fakeClock := srv.Clock().(clockwork.FakeClock)
	mockEmitter := &events.MockEmitter{}
	srv.Auth().emitter = mockEmitter

	defaultModules := modules.GetModules()
	defer modules.SetModules(defaultModules)
	modules.SetModules(&testWithCloudModules{})

	u, err := createUserWithRecoveryCodes(srv, "otp")
	require.NoError(t, err)

	// Test with recover type 2FA.
	startToken, err := srv.Auth().StartAccountRecovery(ctx, &proto.StartAccountRecoveryRequest{
		Username:     u.username,
		RecoveryCode: []byte(u.recoveryCodes[0]),
		RecoverType:  types.UserTokenUsage_RECOVER_2FA,
	})
	require.NoError(t, err)
	require.Equal(t, UserTokenTypeRecoveryStart, startToken.GetSubKind())
	require.Equal(t, types.UserTokenUsage_RECOVER_2FA, startToken.GetUsage())
	require.Equal(t, startToken.GetURL(), fmt.Sprintf("https://<proxyhost>:3080/web/recovery/steps/%s/verify", startToken.GetName()))

	// Test token returned correct byte length.
	bytes, err := hex.DecodeString(startToken.GetName())
	require.NoError(t, err)
	require.Len(t, bytes, RecoveryTokenLenBytes)

	// Test expired token.
	fakeClock.Advance(defaults.RecoveryStartTokenTTL)
	_, err = srv.Auth().GetUserToken(ctx, startToken.GetName())
	require.True(t, trace.IsNotFound(err))

	// Test events emitted.
	event := mockEmitter.LastEvent()
	require.Equal(t, event.GetType(), events.RecoveryTokenCreateEvent)
	require.Equal(t, event.GetCode(), events.RecoveryTokenCreateCode)
	require.Equal(t, event.(*apievents.UserTokenCreate).Name, u.username)

	// Test with recover type PWD.
	startToken, err = srv.Auth().StartAccountRecovery(ctx, &proto.StartAccountRecoveryRequest{
		Username:     u.username,
		RecoveryCode: []byte(u.recoveryCodes[1]),
		RecoverType:  types.UserTokenUsage_RECOVER_PWD,
	})
	require.NoError(t, err)
	require.Equal(t, types.UserTokenUsage_RECOVER_PWD, startToken.GetUsage())

	// Test with no recover type.
	_, err = srv.Auth().StartAccountRecovery(ctx, &proto.StartAccountRecoveryRequest{
		Username:     u.username,
		RecoveryCode: []byte(u.recoveryCodes[2]),
	})
	require.Error(t, err)
}

func TestStartAccountRecovery_WithLock(t *testing.T) {
	srv := newTestTLSServer(t)
	ctx := context.Background()
	fakeClock := srv.Clock().(clockwork.FakeClock)

	defaultModules := modules.GetModules()
	defer modules.SetModules(defaultModules)
	modules.SetModules(&testWithCloudModules{})

	u, err := createUserWithRecoveryCodes(srv, "otp")
	require.NoError(t, err)

	// Test max failed recovery attempt locks both login and further recovery attempt.
	for i := 1; i <= defaults.MaxAccountRecoveryAttempts; i++ {
		_, err = srv.Auth().StartAccountRecovery(ctx, &proto.StartAccountRecoveryRequest{
			Username: u.username,
		})
		require.Error(t, err)
	}

	user, err := srv.Auth().GetUser(u.username, false)
	require.NoError(t, err)
	require.True(t, user.GetStatus().IsLocked)
	require.False(t, user.GetStatus().LockExpires.IsZero())
	require.False(t, user.GetStatus().RecoveryAttemptLockExpires.IsZero())

	// Advance time to remove lock and attempts.
	fakeClock.Advance(defaults.AttemptTTL)

	// Trigger login lock.
	triggerLoginLock(t, srv.Auth(), u.username)

	// Test recovery is still allowed after login lock.
	_, err = srv.Auth().StartAccountRecovery(ctx, &proto.StartAccountRecoveryRequest{
		Username:     u.username,
		RecoveryCode: []byte(u.recoveryCodes[0]),
		RecoverType:  types.UserTokenUsage_RECOVER_2FA,
	})
	require.NoError(t, err)

	// Trigger max failed recovery attempts.
	for i := 1; i <= defaults.MaxAccountRecoveryAttempts; i++ {
		_, err = srv.Auth().StartAccountRecovery(ctx, &proto.StartAccountRecoveryRequest{
			Username: u.username,
		})
		require.Error(t, err)

		// The third failed attempt should return error.
		if i == defaults.MaxAccountRecoveryAttempts {
			require.EqualValues(t, ErrMaxFailedAttemptsFromStartRecovery, err)
		}
	}

	// Test recovery is denied from attempt recovery lock.
	_, err = srv.Auth().StartAccountRecovery(ctx, &proto.StartAccountRecoveryRequest{
		Username:     u.username,
		RecoveryCode: []byte(u.recoveryCodes[1]),
		RecoverType:  types.UserTokenUsage_RECOVER_2FA,
	})
	require.True(t, trace.IsAccessDenied(err))
}

// TestApproveAccountRecoveryExtended_WithPassword tests obtaining approval token
// with password authn along with testing for:
//   - events emitted
//   - start tokens are deleted with success
//   - approved tokens are set to expire at correct time
//   - getting login locked does not prevent user from recovering
//   - check recovery attempts are reset with success
func TestApproveAccountRecoveryExtended_WithPassword(t *testing.T) {
	srv := newTestTLSServer(t)
	ctx := context.Background()
	fakeClock := srv.Clock().(clockwork.FakeClock)
	mockEmitter := &events.MockEmitter{}
	srv.Auth().emitter = mockEmitter

	defaultModules := modules.GetModules()
	defer modules.SetModules(defaultModules)
	modules.SetModules(&testWithCloudModules{})

	u, err := createUserWithRecoveryCodes(srv, "otp")
	require.NoError(t, err)

	// Login locks should not affect attempting to get approval.
	triggerLoginLock(t, srv.Auth(), u.username)

	// Step 1: acquire a start token requesting to recover a second factor.
	startToken, err := srv.Auth().createRecoveryToken(ctx, u.username, UserTokenTypeRecoveryStart, types.UserTokenUsage_RECOVER_2FA)
	require.NoError(t, err)

	// Step 2: approve the request with a user's password, which is required to recover a second factor.
	approvedToken, err := srv.Auth().ApproveAccountRecovery(ctx, &proto.ApproveAccountRecoveryRequest{
		RecoveryStartTokenID: startToken.GetName(),
		Username:             u.username,
		AuthnCred:            &proto.ApproveAccountRecoveryRequest_Password{Password: u.password},
	})
	require.NoError(t, err)
	require.Equal(t, UserTokenTypeRecoveryApproved, approvedToken.GetSubKind())
	require.Equal(t, types.UserTokenUsage_RECOVER_2FA.String(), approvedToken.GetUsage().String())

	// Test events emitted.
	event := mockEmitter.LastEvent()
	require.Equal(t, event.GetType(), events.RecoveryTokenCreateEvent)
	require.Equal(t, event.GetCode(), events.RecoveryTokenCreateCode)
	require.Equal(t, event.(*apievents.UserTokenCreate).Name, u.username)

	// Test start token got deleted.
	_, err = srv.Auth().GetUserToken(ctx, startToken.GetName())
	require.True(t, trace.IsNotFound(err))

	// Test expired token.
	fakeClock.Advance(defaults.RecoveryApprovedTokenTTL)
	_, err = srv.Auth().GetUserToken(ctx, approvedToken.GetName())
	require.True(t, trace.IsNotFound(err))

	// Test recovery attempts are deleted.
	attempts, err := srv.Auth().GetUserRecoveryAttempts(ctx, u.username)
	require.NoError(t, err)
	require.Len(t, attempts, 0)
}

func TestApproveAccountRecovery_WithTOTP(t *testing.T) {
	srv := newTestTLSServer(t)
	ctx := context.Background()

	defaultModules := modules.GetModules()
	defer modules.SetModules(defaultModules)
	modules.SetModules(&testWithCloudModules{})

	// Test with a user with totp device.
	u, err := createUserWithRecoveryCodes(srv, "otp")
	require.NoError(t, err)

	// Step 1: acquire a start token requesting to recover a password.
	startToken, err := srv.Auth().createRecoveryToken(ctx, u.username, UserTokenTypeRecoveryStart, types.UserTokenUsage_RECOVER_PWD)
	require.NoError(t, err)

	// Get a new totp code for our existing device.
	newOTP, err := totp.GenerateCode(u.otpKey, srv.Clock().Now().Add(30*time.Second))
	require.NoError(t, err)

	// Step 2: approve the request with a user's second factor, which is required to recover a password.
	approvedToken, err := srv.Auth().ApproveAccountRecovery(ctx, &proto.ApproveAccountRecoveryRequest{
		RecoveryStartTokenID: startToken.GetName(),
		Username:             u.username,
		AuthnCred: &proto.ApproveAccountRecoveryRequest_MFAAuthenticateResponse{MFAAuthenticateResponse: &proto.MFAAuthenticateResponse{
			Response: &proto.MFAAuthenticateResponse_TOTP{TOTP: &proto.TOTPResponse{Code: newOTP}},
		}},
	})
	require.NoError(t, err)
	require.Equal(t, UserTokenTypeRecoveryApproved, approvedToken.GetSubKind())
	require.Equal(t, types.UserTokenUsage_RECOVER_PWD.String(), approvedToken.GetUsage().String())
}

func TestApproveAccountRecovery_WithU2F(t *testing.T) {
	srv := newTestTLSServer(t)
	ctx := context.Background()

	defaultModules := modules.GetModules()
	defer modules.SetModules(defaultModules)
	modules.SetModules(&testWithCloudModules{})

	// Test with a user with u2f device.
	u, err := createUserWithRecoveryCodes(srv, "u2f")
	require.NoError(t, err)

	// Step 1: acquire a start token requesting to recover a password.
	startToken, err := srv.Auth().createRecoveryToken(ctx, u.username, UserTokenTypeRecoveryStart, types.UserTokenUsage_RECOVER_PWD)
	require.NoError(t, err)

	// Sign a u2f challenge for our existing device.
	chal, err := srv.Auth().mfaAuthChallenge(ctx, u.username, srv.Auth().Identity)
	require.NoError(t, err)

	u2f, err := u.u2fKey.SignResponse(&u2f.SignRequest{
		Version:   chal.GetU2F()[0].Version,
		Challenge: chal.GetU2F()[0].Challenge,
		KeyHandle: chal.GetU2F()[0].KeyHandle,
		AppID:     chal.GetU2F()[0].AppID,
	})
	require.NoError(t, err)

	// Step 2: approve the request with a user's second factor, which is required to recover a password.
	approvedToken, err := srv.Auth().ApproveAccountRecovery(ctx, &proto.ApproveAccountRecoveryRequest{
		RecoveryStartTokenID: startToken.GetName(),
		Username:             u.username,
		AuthnCred: &proto.ApproveAccountRecoveryRequest_MFAAuthenticateResponse{MFAAuthenticateResponse: &proto.MFAAuthenticateResponse{
			Response: &proto.MFAAuthenticateResponse_U2F{U2F: &proto.U2FResponse{
				KeyHandle:  u2f.KeyHandle,
				ClientData: u2f.ClientData,
				Signature:  u2f.SignatureData,
			}},
		}},
	})
	require.NoError(t, err)
	require.Equal(t, UserTokenTypeRecoveryApproved, approvedToken.GetSubKind())
	require.Equal(t, types.UserTokenUsage_RECOVER_PWD.String(), approvedToken.GetUsage().String())
}

func TestApproveAccountRecovery_WithLock(t *testing.T) {
	srv := newTestTLSServer(t)
	ctx := context.Background()
	mockEmitter := &events.MockEmitter{}
	srv.Auth().emitter = mockEmitter

	defaultModules := modules.GetModules()
	defer modules.SetModules(defaultModules)
	modules.SetModules(&testWithCloudModules{})

	u, err := createUserWithRecoveryCodes(srv, "")
	require.NoError(t, err)

	// Acquire a start token.
	startToken, err := srv.Auth().createRecoveryToken(ctx, u.username, UserTokenTypeRecoveryStart, types.UserTokenUsage_RECOVER_2FA)
	require.NoError(t, err)

	// Trigger max failed recovery attempts.
	for i := 1; i <= defaults.MaxAccountRecoveryAttempts; i++ {
		_, err = srv.Auth().ApproveAccountRecovery(ctx, &proto.ApproveAccountRecoveryRequest{
			RecoveryStartTokenID: startToken.GetName(),
			Username:             u.username,
			AuthnCred:            &proto.ApproveAccountRecoveryRequest_Password{Password: []byte("wrong-password")},
		})
		require.Error(t, err)

		// The third failed attempt should return error.
		if i == defaults.MaxAccountRecoveryAttempts {
			require.EqualValues(t, ErrMaxFailedAttemptsFromApproveRecovery, err)
		}
	}

	// Test start token is deleted from max failed attempts.
	_, err = srv.Auth().GetUserToken(ctx, startToken.GetName())
	require.True(t, trace.IsNotFound(err))

	// Test only login is locked.
	user, err := srv.Auth().GetUser(u.username, false)
	require.NoError(t, err)
	require.True(t, user.GetStatus().IsLocked)
	require.True(t, user.GetStatus().RecoveryAttemptLockExpires.IsZero())
	require.False(t, user.GetStatus().LockExpires.IsZero())

	// Test recovery attempts got reset.
	attempts, err := srv.Auth().GetUserRecoveryAttempts(ctx, u.username)
	require.NoError(t, err)
	require.Len(t, attempts, 0)
}

type userAuthCreds struct {
	recoveryCodes []string
	username      string
	password      []byte
	u2fKey        *mocku2f.Key
	otpKey        string
}

func triggerLoginLock(t *testing.T, srv *Server, username string) {
	for i := 1; i <= defaults.MaxLoginAttempts; i++ {
		_, err := srv.authenticateUser(context.Background(), AuthenticateUserRequest{
			Username: username,
			OTP:      &OTPCreds{},
		})
		require.Error(t, err)

		if i == defaults.MaxLoginAttempts {
			require.True(t, trace.IsAccessDenied(err))
		}
	}
}

func createUserWithRecoveryCodes(srv *TestTLSServer, secondFactor string) (*userAuthCreds, error) {
	ctx := context.Background()
	username := "fake@fake.com"
	password := []byte("abc123")

	// Enable second factors.
	ap, err := types.NewAuthPreference(types.AuthPreferenceSpecV2{
		Type:         constants.Local,
		SecondFactor: constants.SecondFactorOn,
		U2F: &types.U2F{
			AppID:  "teleport",
			Facets: []string{"teleport"},
		},
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if err := srv.Auth().SetAuthPreference(ctx, ap); err != nil {
		return nil, trace.Wrap(err)
	}

	_, _, err = CreateUserAndRole(srv.Auth(), username, []string{username})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Insert a password.
	if err = srv.Auth().UpsertPassword(username, password); err != nil {
		return nil, trace.Wrap(err)
	}

	// Insert recovery codes.
	recoveryCodes, err := srv.Auth().generateAndUpsertRecoveryCodes(ctx, username)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Create a token required to insert a mfa device.
	resetToken, err := srv.Auth().CreateUserToken(ctx, &types.UserTokenV3{
		SubKind:  UserTokenTypeResetPassword,
		Metadata: types.Metadata{Name: "token-id-does-not-matter"},
		Spec:     types.UserTokenSpecV3{User: username},
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Add second factor.
	if secondFactor == "otp" {
		otpToken, otpKey, err := getOTPCode(srv, resetToken.GetName())
		if err != nil {
			return nil, trace.Wrap(err)
		}

		err = srv.Auth().changeUserSecondFactor(&proto.ChangeUserAuthenticationRequest{
			TokenID: resetToken.GetName(),
			NewMFARegisterResponse: &proto.MFARegisterResponse{Response: &proto.MFARegisterResponse_TOTP{
				TOTP: &proto.TOTPRegisterResponse{Code: otpToken},
			}},
		}, resetToken)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		return &userAuthCreds{
			recoveryCodes: recoveryCodes,
			username:      username,
			password:      password,
			otpKey:        otpKey,
		}, nil
	}

	if secondFactor == "u2f" {
		u2fRegResp, u2fKey, err := getMockedU2FAndRegisterRes(srv, resetToken.GetName())
		if err != nil {
			return nil, trace.Wrap(err)
		}

		err = srv.Auth().changeUserSecondFactor(&proto.ChangeUserAuthenticationRequest{
			TokenID: resetToken.GetName(),
			NewMFARegisterResponse: &proto.MFARegisterResponse{Response: &proto.MFARegisterResponse_U2F{
				U2F: &proto.U2FRegisterResponse{
					RegistrationData: u2fRegResp.RegistrationData,
					ClientData:       u2fRegResp.ClientData,
				},
			}},
		}, resetToken)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		return &userAuthCreds{
			recoveryCodes: recoveryCodes,
			username:      username,
			password:      password,
			u2fKey:        u2fKey,
		}, nil
	}

	return &userAuthCreds{
		username:      username,
		password:      password,
		recoveryCodes: recoveryCodes,
	}, nil
}

func getOTPCode(srv *TestTLSServer, tokenID string) (string, string, error) {
	secrets, err := srv.Auth().RotateUserTokenSecrets(context.TODO(), tokenID)
	if err != nil {
		return "", "", trace.Wrap(err)
	}

	otpToken, err := totp.GenerateCode(secrets.GetOTPKey(), srv.Clock().Now())
	if err != nil {
		return "", "", trace.Wrap(err)
	}

	return otpToken, secrets.GetOTPKey(), nil
}

func getMockedU2FAndRegisterRes(srv *TestTLSServer, tokenID string) (*proto.U2FRegisterResponse, *mocku2f.Key, error) {
	res, err := srv.Auth().CreateSignupU2FRegisterRequest(tokenID)
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}

	u2fKey, err := mocku2f.Create()
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}

	u2fRegResp, err := u2fKey.RegisterResponse(res)
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}

	return &proto.U2FRegisterResponse{
		RegistrationData: u2fRegResp.RegistrationData,
		ClientData:       u2fRegResp.ClientData,
	}, u2fKey, nil
}
