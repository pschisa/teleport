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
	"net/mail"
	"strings"
	"time"

	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/types"
	apievents "github.com/gravitational/teleport/api/types/events"
	apiutils "github.com/gravitational/teleport/api/utils"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/modules"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/trace"

	"github.com/sethvargo/go-diceware/diceware"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

const (
	numOfRecoveryCodes     = 3
	numWordsInRecoveryCode = 8

	// accountLockedMsg is the reason used to update a user's status locked message.
	accountLockedMsg = "user has exceeded maximum failed account recovery attempts"
)

// fakeRecoveryCodeHash is bcrypt hash for "fake-barbaz x 8".
// This is a fake hash used to mitigate timing attacks against invalid usernames or if user does
// exist but does not have recovery codes.
var fakeRecoveryCodeHash = []byte(`$2a$10$c2.h4pF9AA25lbrWo6U0D.ZmnYpFDaNzN3weNNYNC3jAkYEX9kpzu`)

// ErrMaxFailedAttemptsFromStartRecovery is a user friendly error message. This error is defined in a variable so that the root caller
// can determine if an email needs to be sent.
var ErrMaxFailedAttemptsFromStartRecovery = trace.AccessDenied("too many incorrect attempts, please try again later")

// ErrMaxFailedAttemptsFromApproveRecovery is a user friendly error message. This error is defined in a variable so that the root caller
// can determine if an email needs to be sent.
var ErrMaxFailedAttemptsFromApproveRecovery = trace.AccessDenied("too many incorrect attempts, please start over with a new recovery code")

// StartAccountRecovery implements AuthService.StartAccountRecovery.
func (s *Server) StartAccountRecovery(ctx context.Context, req *proto.StartAccountRecoveryRequest) (types.UserToken, error) {
	if err := s.isAccountRecoveryAllowed(ctx); err != nil {
		return nil, trace.Wrap(err)
	}

	// Only user's with email as their username can start recovery.
	if _, err := mail.ParseAddress(req.GetUsername()); err != nil {
		return nil, trace.BadParameter("only emails as usernames are allowed to recover their account")
	}

	if err := s.verifyCodeWithRecoveryLock(ctx, req.GetUsername(), req.GetRecoveryCode()); err != nil {
		return nil, trace.Wrap(err)
	}

	// Remove any other existing tokens for this user before creating a token.
	if err := s.deleteUserTokens(ctx, req.Username); err != nil {
		return nil, trace.Wrap(err)
	}

	token, err := s.createRecoveryToken(ctx, req.GetUsername(), UserTokenTypeRecoveryStart, req.GetRecoverType())
	return token, trace.Wrap(err)
}

// verifyCodeWithRecoveryLock counts number of failed attempts at providing a valid recovery code.
// After MaxAccountRecoveryAttempts, user is temporarily locked from further attempts at recovering and also
// locked from logging in. Modeled after existing function WithUserLock.
func (s *Server) verifyCodeWithRecoveryLock(ctx context.Context, username string, recoveryCode []byte) error {
	user, err := s.Identity.GetUser(username, false)
	if err != nil {
		if trace.IsNotFound(err) {
			// If user is not found, still authenticate. It should
			// always return an error. This prevents username oracles and
			// timing attacks.
			return s.verifyRecoveryCode(ctx, username, recoveryCode)
		}
		return trace.Wrap(err)
	}

	status := user.GetStatus()
	if status.IsLocked && status.RecoveryAttemptLockExpires.After(s.clock.Now().UTC()) {
		log.Debugf("%v exceeds %v failed account recovery attempts, locked until %v",
			user.GetName(), defaults.MaxAccountRecoveryAttempts, apiutils.HumanTimeFormat(status.RecoveryAttemptLockExpires))
		return trace.AccessDenied("too many incorrect attempts, please try again later")
	}

	fnErr := s.verifyRecoveryCode(ctx, username, recoveryCode)
	if fnErr == nil {
		return nil
	}

	lockedUntil, err := s.recordFailedRecoveryAttempt(ctx, fnErr, username)
	if err != nil {
		return trace.Wrap(err)
	}

	// Temp lock both user login and recovery attempts.
	user.SetLockedFromRecoveryAttempt(*lockedUntil)
	user.SetLocked(*lockedUntil, accountLockedMsg)

	if err := s.Identity.UpsertUser(user); err != nil {
		log.Error(trace.DebugReport(err))
		return trace.Wrap(fnErr)
	}

	return ErrMaxFailedAttemptsFromStartRecovery
}

func (s *Server) verifyRecoveryCode(ctx context.Context, user string, givenCode []byte) error {
	recovery, err := s.GetRecoveryCodes(ctx, user)
	if err != nil && !trace.IsNotFound(err) {
		return trace.Wrap(err)
	}

	hashedCodes := make([]types.RecoveryCode, numOfRecoveryCodes)
	hasRecoveryCodes := false
	if trace.IsNotFound(err) {
		log.Debugf("Account recovery codes for user %q not found, using fake hashes to mitigate timing attacks.", user)
		for i := 0; i < numOfRecoveryCodes; i++ {
			hashedCodes[i].HashedCode = fakeRecoveryCodeHash
		}
	} else {
		hasRecoveryCodes = true
		hashedCodes = recovery.GetCodes()
	}

	codeMatch := false
	for i, code := range hashedCodes {
		// Always take the time to check, but ignore the result if the code was
		// previously used or if checking against fakes.
		err := bcrypt.CompareHashAndPassword(code.HashedCode, givenCode)
		if err != nil || code.IsUsed || !hasRecoveryCodes {
			continue
		}
		codeMatch = true
		// Mark matched token as used in backend so it can't be used again.
		recovery.GetCodes()[i].IsUsed = true
		if err := s.UpsertRecoveryCodes(ctx, user, recovery); err != nil {
			return trace.Wrap(err)
		}
		break
	}

	event := &apievents.RecoveryCodeUsed{
		Metadata: apievents.Metadata{
			Type: events.RecoveryCodeUsedEvent,
			Code: events.RecoveryCodeUseSuccessCode,
		},
		UserMetadata: apievents.UserMetadata{
			User: user,
		},
		Status: apievents.Status{
			Success: true,
		},
	}

	if !codeMatch || !hasRecoveryCodes {
		event.Status.Success = false
		event.Metadata.Code = events.RecoveryCodeUseFailureCode
		traceErr := trace.NotFound("invalid user or user does not have recovery codes")

		if hasRecoveryCodes {
			traceErr = trace.BadParameter("recovery code did not match")
		}

		event.Status.Error = traceErr.Error()
		event.Status.UserMessage = traceErr.Error()

		if err := s.emitter.EmitAuditEvent(s.closeCtx, event); err != nil {
			log.WithFields(logrus.Fields{"user": user}).Warn("Failed to emit account recovery code used failed event.")
		}

		return trace.BadParameter("invalid username or recovery code")
	}

	if err := s.emitter.EmitAuditEvent(s.closeCtx, event); err != nil {
		log.WithFields(logrus.Fields{"user": user}).Warn("Failed to emit account recovery code used event.")
	}

	return nil
}

// ApproveAccountRecovery implements AuthService.ApproveAccountRecovery.
func (s *Server) ApproveAccountRecovery(ctx context.Context, req *proto.ApproveAccountRecoveryRequest) (types.UserToken, error) {
	if err := s.isAccountRecoveryAllowed(ctx); err != nil {
		return nil, trace.Wrap(err)
	}

	token, err := s.GetUserToken(ctx, req.GetRecoveryStartTokenID())
	if err != nil {
		// User can get this error from maxing out attempts.
		// Return a user friendly message to notify user to start over.
		if trace.IsNotFound(err) {
			return nil, trace.BadParameter("please start over with a new recovery code")
		}
		return nil, trace.Wrap(err)
	}

	if err := s.verifyUserToken(token, UserTokenTypeRecoveryStart); err != nil {
		// Provide obscure message on purpose, while logging the real error server side.
		log.Debugf("Unable to approve account recovery request with token(%s) type(%s)", token.GetName(), token.GetSubKind())
		return nil, trace.AccessDenied("access denied")
	}

	if token.GetUser() != req.Username {
		return nil, trace.BadParameter("invalid username")
	}

	// Check that correct authentication is provided before verifying.
	switch req.GetAuthnCred().(type) {
	case *proto.ApproveAccountRecoveryRequest_Password:
		if token.GetUsage() == types.UserTokenUsage_RECOVER_PWD {
			return nil, trace.BadParameter("unexpected password credential")
		}

		approvedToken, err := s.verifyAuthnWithRecoveryLock(ctx, token, func() error {
			return s.checkPasswordWOToken(token.GetUser(), req.GetPassword())
		})

		return approvedToken, trace.Wrap(err)

	case *proto.ApproveAccountRecoveryRequest_MFAAuthenticateResponse:
		if token.GetUsage() == types.UserTokenUsage_RECOVER_2FA {
			return nil, trace.BadParameter("unexpected second factor credential")
		}

		approvedToken, err := s.verifyAuthnWithRecoveryLock(ctx, token, func() error {
			_, err := s.validateMFAAuthResponse(ctx, token.GetUser(), req.GetMFAAuthenticateResponse(), s.Identity)
			return err
		})

		return approvedToken, trace.Wrap(err)
	}

	return nil, trace.BadParameter("at least one authentication method required")
}

// verifyAuthnWithRecoveryLock counts number of failed attempts at providing a valid password or second factor.
// After MaxAccountRecoveryAttempts, user's account is temporarily locked from logging in, recovery attempts are reset,
// and all user's tokens are deleted. Modeled after existing function WithUserLock.
func (s *Server) verifyAuthnWithRecoveryLock(ctx context.Context, startToken types.UserToken, authenticateFn func() error) (types.UserToken, error) {
	user, err := s.Identity.GetUser(startToken.GetUser(), false)
	if err != nil {
		if trace.IsNotFound(err) {
			// If user is not found, still call authenticateFn. It should
			// always return an error. This prevents username oracles and
			// timing attacks.
			return nil, authenticateFn()
		}
		return nil, trace.Wrap(err)
	}

	fnErr := authenticateFn()
	if fnErr == nil {
		// Delete start token to invalidate the recovery link sent to users.
		if err := s.DeleteUserToken(ctx, startToken.GetName()); err != nil {
			return nil, trace.Wrap(err)
		}

		if err := s.DeleteUserRecoveryAttempts(ctx, startToken.GetUser()); err != nil {
			return nil, trace.Wrap(err)
		}

		approvedToken, err := s.createRecoveryToken(ctx, startToken.GetUser(), UserTokenTypeRecoveryApproved, startToken.GetUsage())
		if err != nil {
			return nil, trace.Wrap(err)
		}

		return approvedToken, nil
	}

	lockedUntil, err := s.recordFailedRecoveryAttempt(ctx, fnErr, startToken.GetUser())
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Delete all tokens related to this user, to force user to restart the recovery flow.
	if err := s.deleteUserTokens(ctx, startToken.GetUser()); err != nil {
		log.Error(trace.DebugReport(err))
		return nil, trace.Wrap(fnErr)
	}

	// Restart the attempt counter, to allow user to use remaining unused recovery codes.
	if err := s.DeleteUserRecoveryAttempts(ctx, startToken.GetUser()); err != nil {
		log.Error(trace.DebugReport(err))
		return nil, trace.Wrap(fnErr)
	}

	// Only lock the user from logging in.
	user.SetLocked(*lockedUntil, accountLockedMsg)
	if err := s.Identity.UpsertUser(user); err != nil {
		log.Error(trace.DebugReport(err))
		return nil, trace.Wrap(fnErr)
	}

	return nil, ErrMaxFailedAttemptsFromApproveRecovery
}

// recordFailedRecoveryAttempt creates and inserts a recovery attempt and if user has reached max failed attempts,
// returns the locked until time.
func (s *Server) recordFailedRecoveryAttempt(ctx context.Context, rootErr error, username string) (*time.Time, error) {
	// Do not lock user in case if DB is flaky or down.
	if trace.IsConnectionProblem(rootErr) {
		return nil, trace.Wrap(rootErr)
	}

	// Log failed attempt.
	now := s.clock.Now().UTC()
	attempt := &types.RecoveryAttempt{Time: now, Expires: now.Add(defaults.AttemptTTL)}
	if err := s.CreateUserRecoveryAttempt(ctx, username, attempt); err != nil {
		log.Error(trace.DebugReport(err))
		return nil, trace.Wrap(rootErr)
	}

	attempts, err := s.Identity.GetUserRecoveryAttempts(ctx, username)
	if err != nil {
		log.Error(trace.DebugReport(err))
		return nil, trace.Wrap(rootErr)
	}

	if !types.IsMaxFailedRecoveryAttempt(defaults.MaxAccountRecoveryAttempts, attempts, now) {
		log.Debugf("%v user has less than %v failed account recovery attempts", username, defaults.MaxAccountRecoveryAttempts)
		return nil, trace.Wrap(rootErr)
	}

	// Reached max attempts.
	lockUntil := s.clock.Now().UTC().Add(defaults.AccountLockInterval)

	log.Debugf("%v exceeds %v failed account recovery attempts, account locked until %v and an email has been sent",
		username, defaults.MaxAccountRecoveryAttempts, apiutils.HumanTimeFormat(lockUntil))

	return &lockUntil, nil
}

// ChangeAuthnFromAccountRecovery implements AuthService.ChangeAuthnFromAccountRecovery.
func (s *Server) ChangeAuthnFromAccountRecovery(ctx context.Context, req *proto.ChangeAuthnFromAccountRecoveryRequest) error {
	if err := s.isAccountRecoveryAllowed(ctx); err != nil {
		return trace.Wrap(err)
	}

	approvedToken, err := s.GetUserToken(ctx, req.GetRecoveryApprovedTokenID())
	if err != nil {
		return trace.Wrap(err)
	}

	if err := s.verifyUserToken(approvedToken, UserTokenTypeRecoveryApproved); err != nil {
		// Provide obscure message on purpose, while logging the real error server side.
		log.Debugf("Unable to change authn from account recovery with token(%s) type(%s)", approvedToken.GetName(), approvedToken.GetSubKind())
		return trace.AccessDenied("access denied")
	}

	// Check that the correct auth credential is being recovered before setting a new one.
	switch req.GetNewAuthnCred().(type) {
	case *proto.ChangeAuthnFromAccountRecoveryRequest_NewPassword:
		if approvedToken.GetUsage() == types.UserTokenUsage_RECOVER_2FA {
			return trace.BadParameter("expected new second factor")
		}

		if err := services.VerifyPassword(req.GetNewPassword()); err != nil {
			return trace.Wrap(err)
		}

		if err := s.UpsertPassword(approvedToken.GetUser(), req.GetNewPassword()); err != nil {
			return trace.Wrap(err)
		}

	case *proto.ChangeAuthnFromAccountRecoveryRequest_NewMFAResponse:
		if approvedToken.GetUsage() == types.UserTokenUsage_RECOVER_PWD {
			return trace.BadParameter("expected new password")
		}

		err := s.validateMFARegResponseWithToken(ctx, req.GetNewMFAResponse(), approvedToken, req.GetNewDeviceName())
		switch {
		case trace.IsAlreadyExists(err):
			// Return a shorter friendlier message.
			return trace.AlreadyExists("MFA device with name %q already exists", req.GetNewDeviceName())
		case err != nil:
			return trace.Wrap(err)
		}

	default:
		return trace.BadParameter("at least one new authentication is required")
	}

	// Check and remove user login lock so user can immediately sign in after finishing recovering.
	user, err := s.GetUser(approvedToken.GetUser(), false)
	if err != nil {
		return trace.Wrap(err)
	}

	if user.GetStatus().IsLocked {
		user.ResetLocks()
		if err := s.Identity.UpsertUser(user); err != nil {
			return trace.Wrap(err)
		}

		if err := s.DeleteUserLoginAttempts(approvedToken.GetUser()); err != nil {
			return trace.Wrap(err)
		}
	}

	return nil
}

func (s *Server) generateAndUpsertRecoveryCodes(ctx context.Context, username string) ([]string, error) {
	codes, err := generateRecoveryCodes()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	hashedCodes := make([]types.RecoveryCode, len(codes))
	for i, token := range codes {
		hashedCode, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		hashedCodes[i].HashedCode = hashedCode
	}

	rc, err := types.NewRecoveryCodes(hashedCodes, s.GetClock().Now().UTC(), username)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if err := s.UpsertRecoveryCodes(ctx, username, rc); err != nil {
		return nil, trace.Wrap(err)
	}

	if err := s.emitter.EmitAuditEvent(s.closeCtx, &apievents.RecoveryCodeGenerate{
		Metadata: apievents.Metadata{
			Type: events.RecoveryCodeGeneratedEvent,
			Code: events.RecoveryCodesGenerateCode,
		},
		UserMetadata: apievents.UserMetadata{
			User: username,
		},
	}); err != nil {
		log.WithError(err).WithFields(logrus.Fields{"user": username}).Warn("Failed to emit recovery tokens generate event.")
	}

	return codes, nil
}

// isAccountRecoveryAllowed gets cluster auth configuration and check if cloud, local auth
// and second factor is allowed, which are required for account recovery.
func (s *Server) isAccountRecoveryAllowed(ctx context.Context) error {
	if modules.GetModules().Features().Cloud == false {
		return trace.AccessDenied("account recovery is only available for enterprise cloud")
	}

	authPref, err := s.GetAuthPreference(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	if !authPref.GetAllowLocalAuth() {
		return trace.AccessDenied("local auth needs to be enabled")
	}

	if !authPref.IsSecondFactorEnforced() {
		return trace.AccessDenied("second factor must be enabled")
	}

	return nil
}

// generateRecoveryCodes returns an array of tokens where each token
// have 8 random words prefixed with tele and concanatenated with dashes.
func generateRecoveryCodes() ([]string, error) {
	gen, err := diceware.NewGenerator(nil /* use default word list */)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	tokenList := make([]string, numOfRecoveryCodes)
	for i := 0; i < numOfRecoveryCodes; i++ {
		list, err := gen.Generate(numWordsInRecoveryCode)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		tokenList[i] = "tele-" + strings.Join(list, "-")
	}

	return tokenList, nil
}
