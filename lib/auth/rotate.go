/*
Copyright 2018-2019 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package auth

import (
	"crypto/rsa"
	"crypto/x509/pkix"
	"time"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/sshutils"
	"github.com/gravitational/teleport/lib/tlsca"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"github.com/pborman/uuid"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

// RotateRequest is a request to start rotation of the certificate authority.
type RotateRequest struct {
	// Type is a certificate authority type, if omitted, both user and host CA
	// will be rotated.
	Type types.CertAuthType `json:"type"`
	// GracePeriod is used to generate cert rotation schedule that defines
	// times at which different rotation phases will be applied by the auth server
	// in auto mode. It is not used in manual rotation mode.
	// If omitted, default value is set, if 0 is supplied, it is interpreted as
	// forcing rotation of all certificate authorities with no grace period,
	// all existing users and hosts will have to re-login and re-added
	// into the cluster.
	GracePeriod *time.Duration `json:"grace_period,omitempty"`
	// TargetPhase sets desired rotation phase to move to, if not set
	// will be set automatically, it is a required argument
	// for manual rotation.
	TargetPhase string `json:"target_phase,omitempty"`
	// Mode sets manual or auto rotation mode.
	Mode string `json:"mode"`
	// Schedule is an optional rotation schedule,
	// autogenerated based on GracePeriod parameter if not set.
	Schedule *types.RotationSchedule `json:"schedule"`
}

// Types returns cert authority types requested to be rotated.
func (r *RotateRequest) Types() []types.CertAuthType {
	switch r.Type {
	case "":
		return []types.CertAuthType{types.HostCA, types.UserCA, types.JWTSigner}
	case types.HostCA:
		return []types.CertAuthType{types.HostCA}
	case types.UserCA:
		return []types.CertAuthType{types.UserCA}
	case types.JWTSigner:
		return []types.CertAuthType{types.JWTSigner}
	}
	return nil
}

// CheckAndSetDefaults checks and sets default values.
func (r *RotateRequest) CheckAndSetDefaults(clock clockwork.Clock) error {
	if r.TargetPhase == "" {
		// if phase if not set, imply that the first meaningful phase
		// is set as a target phase
		r.TargetPhase = types.RotationPhaseInit
	}
	// if mode is not set, default to manual (as it's safer)
	if r.Mode == "" {
		r.Mode = types.RotationModeManual
	}
	switch r.Type {
	case "", types.HostCA, types.UserCA, types.JWTSigner:
	default:
		return trace.BadParameter("unsupported certificate authority type: %q", r.Type)
	}
	if r.GracePeriod == nil {
		period := defaults.RotationGracePeriod
		r.GracePeriod = &period
	}
	if r.Schedule == nil {
		var err error
		r.Schedule, err = types.GenerateSchedule(clock.Now(), *r.GracePeriod)
		if err != nil {
			return trace.Wrap(err)
		}
	} else {
		if err := r.Schedule.CheckAndSetDefaults(clock.Now()); err != nil {
			return trace.Wrap(err)
		}
	}
	return nil
}

// rotationReq is an internal rotation requrest
type rotationReq struct {
	// clock implements test or real wall clock
	clock clockwork.Clock
	// ca is a certificate authority to rotate
	ca types.CertAuthority
	// targetPhase is a target rotation phase to set
	targetPhase string
	// mode is a rotation mode
	mode string
	// gracePeriod is a rotation grace period
	gracePeriod time.Duration
	// schedule is a schedule to set
	schedule types.RotationSchedule
	// privateKey is passed by tests to supply private key for cert authorities
	// instead of generating them on each iteration
	privateKey []byte
	// caSigningAlg is an SSH signing algorithm to use with the new CA.
	caSigningAlg *string
}

// RotateCertAuthority starts or restarts certificate authority rotation process.
//
// Rotation procedure is based on the state machine approach.
//
// Here are the supported rotation states:
//
//  * Standby - the cluster is in standby mode and ready to take action.
//  * In-progress - cluster CA rotation is in progress.
//
// In-progress state is split into multiple phases and the cluster
// can traverse between phases using supported transitions.
//
// Here are the supported phases:
//
// * Standby - no action is taken.
//
// * Init - New CAs are issued, but all internal system clients
// and servers are still using the old certificates. New CAs are trusted,
// but are not used. New components that are joining the cluster
// are issued certificates signed by "old" CAs.
//
// This phase is necessary for remote clusters to fetch new certificate authorities,
// otherwise remote clusters will be locked out, because they won't have a chance
// to discover the new certificate authorities to be issued.
//
// * Update Clients - All internal system clients
// have to reconnect and receive the new credentials, but all servers
// TLS, SSH and Proxies will still use old credentials.
// Certs from old CA and new CA are trusted within the system.
// This phase is necessary because old clients should receive new credentials
// from the auth servers. If this phase did not exist, old clients could not
// trust servers serving new credentials, because old clients did not receive
// new information yet. It is possible to transition from this phase to phase
// "Update servers" or "Rollback".
//
// * Update Servers - triggers all internal system components to reload and use
// new credentials both in the internal clients and servers, however
// old CA issued credentials are still trusted. This is done to make it possible
// for old components to be trusted within the system, to make rollback possible.
// It is possible to transition from this phase to "Rollback" or "Standby".
// When transitioning to "Standby" phase, the rotation is considered completed,
// old CA is removed from the system and components reload again,
// but this time they don't trust old CA any more.
//
// * Rollback phase is used to revert any changes. When going to rollback phase
// the newly issued CA is no longer used, but set up as trusted,
// so components can reload and receive credentials issued by "old" CA back.
// This phase is useful when administrator makes a mistake, or there are some
// offline components that will loose the connection in case if rotation
// completes. It is only possible to transition from this phase to "Standby".
// When transitioning to "Standby" phase from "Rollback" phase, all components
// reload again, but the "new" CA is discarded and is no longer trusted,
// cluster goes back to the original state.
//
// Rotation modes
//
// There are two rotation modes supported - manual or automatic.
//
// * Manual mode allows administrators to transition between
// phases explicitly setting a phase on every request.
//
// * Automatic mode performs automatic transition between phases
// on a given schedule. Schedule is a time table
// that specifies exact date when the next phase should take place. If automatic
// transition between any phase fails, the rotation switches back to the manual
// mode and stops execution phases on the schedule. If schedule is not specified,
// it will be auto generated based on the "grace period" duration parameter,
// and time between all phases will be evenly split over the grace period duration.
//
// It is possible to switch from automatic to manual by setting the phase
// to the rollback phase.
//
func (a *Server) RotateCertAuthority(req RotateRequest) error {
	if err := req.CheckAndSetDefaults(a.clock); err != nil {
		return trace.Wrap(err)
	}
	clusterName, err := a.GetClusterName()
	if err != nil {
		return trace.Wrap(err)
	}

	caTypes := req.Types()
	for _, caType := range caTypes {
		existing, err := a.Trust.GetCertAuthority(types.CertAuthID{
			Type:       caType,
			DomainName: clusterName.GetClusterName(),
		}, true)
		if err != nil {
			return trace.Wrap(err)
		}

		rotated, err := a.processRotationRequest(rotationReq{
			ca:           existing,
			clock:        a.clock,
			targetPhase:  req.TargetPhase,
			schedule:     *req.Schedule,
			gracePeriod:  *req.GracePeriod,
			mode:         req.Mode,
			privateKey:   a.privateKey,
			caSigningAlg: a.caSigningAlg,
		})
		if err != nil {
			return trace.Wrap(err)
		}
		if err := a.CompareAndSwapCertAuthority(rotated, existing); err != nil {
			return trace.Wrap(err)
		}
		rotation := rotated.GetRotation()
		switch rotation.State {
		case types.RotationStateInProgress:
			log.WithFields(logrus.Fields{"type": caType}).Infof("Updated rotation state, set current phase to: %q.", rotation.Phase)
		case types.RotationStateStandby:
			log.WithFields(logrus.Fields{"type": caType}).Infof("Updated and completed rotation.")
		}
	}
	return nil
}

// RotateExternalCertAuthority rotates external certificate authority,
// this method is called by remote trusted cluster and is used to update
// only public keys and certificates of the certificate authority.
func (a *Server) RotateExternalCertAuthority(ca types.CertAuthority) error {
	if ca == nil {
		return trace.BadParameter("missing certificate authority")
	}
	clusterName, err := a.GetClusterName()
	if err != nil {
		return trace.Wrap(err)
	}

	// this is just an extra precaution against local admins,
	// because this is additionally enforced by RBAC as well
	if ca.GetClusterName() == clusterName.GetClusterName() {
		return trace.BadParameter("can not rotate local certificate authority")
	}

	existing, err := a.Trust.GetCertAuthority(types.CertAuthID{
		Type:       ca.GetType(),
		DomainName: ca.GetClusterName(),
	}, false)
	if err != nil {
		return trace.Wrap(err)
	}

	updated := existing.Clone()
	if err := updated.SetActiveKeys(ca.GetActiveKeys().Clone()); err != nil {
		return trace.Wrap(err)
	}
	if err := updated.SetAdditionalTrustedKeys(ca.GetAdditionalTrustedKeys().Clone()); err != nil {
		return trace.Wrap(err)
	}
	updated.SetRotation(ca.GetRotation())

	// use compare and swap to protect from concurrent updates
	// by trusted cluster API
	if err := a.CompareAndSwapCertAuthority(updated, existing); err != nil {
		return trace.Wrap(err)
	}

	return nil
}

// autoRotateCertAuthorities automatically rotates cert authorities,
// does nothing if no rotation parameters were set up
// or it is too early to rotate per schedule
func (a *Server) autoRotateCertAuthorities() error {
	clusterName, err := a.GetClusterName()
	if err != nil {
		return trace.Wrap(err)
	}
	for _, caType := range []types.CertAuthType{types.HostCA, types.UserCA, types.JWTSigner} {
		ca, err := a.Trust.GetCertAuthority(types.CertAuthID{
			Type:       caType,
			DomainName: clusterName.GetClusterName(),
		}, true)
		if err != nil {
			return trace.Wrap(err)
		}
		if err := a.autoRotate(ca); err != nil {
			return trace.Wrap(err)
		}
		// make sure there are local AdditionalKeys during init phase of rotation
		if ca.GetRotation().Phase == types.RotationPhaseInit {
			if err := a.ensureLocalAdditionalKeys(ca); err != nil {
				return trace.Wrap(err)
			}
		}
	}
	return nil
}

func (a *Server) autoRotate(ca types.CertAuthority) error {
	rotation := ca.GetRotation()
	// rotation mode is not automatic, nothing to do
	if rotation.Mode != types.RotationModeAuto {
		return nil
	}
	// rotation is not in progress, there is nothing to do
	if rotation.State != types.RotationStateInProgress {
		return nil
	}
	logger := log.WithFields(logrus.Fields{"type": ca.GetType()})
	var req *rotationReq
	switch rotation.Phase {
	case types.RotationPhaseInit:
		if rotation.Schedule.UpdateClients.After(a.clock.Now()) {
			return nil
		}
		req = &rotationReq{
			clock:       a.clock,
			ca:          ca,
			targetPhase: types.RotationPhaseUpdateClients,
			mode:        types.RotationModeAuto,
			gracePeriod: rotation.GracePeriod.Duration(),
			schedule:    rotation.Schedule,
		}
	case types.RotationPhaseUpdateClients:
		if rotation.Schedule.UpdateServers.After(a.clock.Now()) {
			return nil
		}
		req = &rotationReq{
			clock:       a.clock,
			ca:          ca,
			targetPhase: types.RotationPhaseUpdateServers,
			mode:        types.RotationModeAuto,
			gracePeriod: rotation.GracePeriod.Duration(),
			schedule:    rotation.Schedule,
		}
	case types.RotationPhaseUpdateServers:
		if rotation.Schedule.Standby.After(a.clock.Now()) {
			return nil
		}
		req = &rotationReq{
			clock:       a.clock,
			ca:          ca,
			targetPhase: types.RotationPhaseStandby,
			mode:        types.RotationModeAuto,
			gracePeriod: rotation.GracePeriod.Duration(),
			schedule:    rotation.Schedule,
		}
	default:
		return trace.BadParameter("phase is not supported: %q", rotation.Phase)
	}
	logger.Infof("Setting rotation phase to %q", req.targetPhase)
	rotated, err := a.processRotationRequest(*req)
	if err != nil {
		return trace.Wrap(err)
	}
	if err := a.CompareAndSwapCertAuthority(rotated, ca); err != nil {
		return trace.Wrap(err)
	}
	logger.Infof("Cert authority rotation request is completed")
	return nil
}

// processRotationRequest processes rotation request based on the target and
// current phase and state.
func (a *Server) processRotationRequest(req rotationReq) (types.CertAuthority, error) {
	rotation := req.ca.GetRotation()
	ca := req.ca.Clone()

	switch req.targetPhase {
	case types.RotationPhaseInit:
		// This is the first stage of the rotation - new certificate authorities
		// are being generated, but no components are using them yet
		switch rotation.State {
		case types.RotationStateStandby, "":
		default:
			return nil, trace.BadParameter("can not initate rotation while another is in progress")
		}
		if err := a.startNewRotation(req, ca); err != nil {
			return nil, trace.Wrap(err)
		}
		return ca, nil
	case types.RotationPhaseUpdateClients:
		// Update client phase clients will start using new credentials
		// and servers will use the existing credentials, but will trust clients
		// with both old and new credentials.
		if rotation.Phase != types.RotationPhaseInit {
			return nil, trace.BadParameter(
				"can only switch to phase %v from %v, current phase is %v",
				types.RotationPhaseUpdateClients,
				types.RotationPhaseInit,
				rotation.Phase)
		}
		if err := updateClients(ca, req.mode); err != nil {
			return nil, trace.Wrap(err)
		}
		return ca, nil
	case types.RotationPhaseUpdateServers:
		// Update server phase uses the new credentials both for servers
		// and clients, but still trusts clients with old credentials.
		if rotation.Phase != types.RotationPhaseUpdateClients {
			return nil, trace.BadParameter(
				"can only switch to phase %v from %v, current phase is %v",
				types.RotationPhaseUpdateServers,
				types.RotationPhaseUpdateClients,
				rotation.Phase)
		}
		// Signal nodes to restart and start serving new signatures
		// by updating the phase.
		rotation.Phase = req.targetPhase
		rotation.Mode = req.mode
		ca.SetRotation(rotation)
		return ca, nil
	case types.RotationPhaseRollback:
		// Rollback moves back both clients and servers to use the old credentials
		// but will trust new credentials.
		switch rotation.Phase {
		case types.RotationPhaseInit, types.RotationPhaseUpdateClients, types.RotationPhaseUpdateServers:
			if err := startRollingBackRotation(ca); err != nil {
				return nil, trace.Wrap(err)
			}
			return ca, nil
		default:
			return nil, trace.BadParameter("can not transition to phase %q from %q phase.", req.targetPhase, rotation.Phase)
		}
	case types.RotationPhaseStandby:
		// Transition to the standby phase moves rotation process
		// to standby, servers will only trust one certificate authority.
		switch rotation.Phase {
		case types.RotationPhaseUpdateServers, types.RotationPhaseRollback:
			completeRotation(req.clock, ca)
			return ca, nil
		default:
			return nil, trace.BadParameter("can not transition to phase %q from %q phase.", req.targetPhase, rotation.Phase)
		}
	default:
		return nil, trace.BadParameter("unsupported phase: %q", req.targetPhase)
	}
}

// startNewRotation starts new rotation. In this phase requests will continue
// to be signed by the old CAKeySet, but a new CAKeySet will be added. This new
// CA can be used to verify requests.
func (a *Server) startNewRotation(req rotationReq, ca types.CertAuthority) error {
	clock := req.clock
	gracePeriod := req.gracePeriod

	rotation := ca.GetRotation()
	id := uuid.New()

	rotation.Mode = req.mode
	rotation.Schedule = req.schedule

	activeKeys := ca.GetActiveKeys()
	additionalKeys := ca.GetAdditionalTrustedKeys()
	var newKeys types.CAKeySet

	// generate keys and certificates:
	if len(req.privateKey) != 0 {
		log.Infof("Generating CA, using pregenerated test private key.")

		rsaKey, err := ssh.ParseRawPrivateKey(req.privateKey)
		if err != nil {
			return trace.Wrap(err)
		}

		if len(activeKeys.SSH) > 0 {
			signer, err := ssh.NewSignerFromKey(rsaKey)
			if err != nil {
				return trace.Wrap(err)
			}
			sshPublicKey := ssh.MarshalAuthorizedKey(signer.PublicKey())
			newKeys.SSH = append(newKeys.SSH, &types.SSHKeyPair{
				PublicKey:      sshPublicKey,
				PrivateKey:     req.privateKey,
				PrivateKeyType: types.PrivateKeyType_RAW,
			})
		}

		if len(activeKeys.TLS) > 0 {
			tlsCert, err := tlsca.GenerateSelfSignedCAWithConfig(tlsca.GenerateCAConfig{
				Signer: rsaKey.(*rsa.PrivateKey),
				Entity: pkix.Name{
					CommonName:   ca.GetClusterName(),
					Organization: []string{ca.GetClusterName()},
				},
				TTL:   defaults.CATTL,
				Clock: req.clock,
			})
			if err != nil {
				return trace.Wrap(err)
			}
			newKeys.TLS = append(newKeys.TLS, &types.TLSKeyPair{
				Cert:    tlsCert,
				Key:     req.privateKey,
				KeyType: types.PrivateKeyType_RAW,
			})
		}

		if len(activeKeys.JWT) > 0 {
			jwtPublicKey, jwtPrivateKey, err := utils.MarshalPrivateKey(rsaKey.(*rsa.PrivateKey))
			if err != nil {
				return trace.Wrap(err)
			}
			newKeys.JWT = append(newKeys.JWT, &types.JWTKeyPair{
				PublicKey:      jwtPublicKey,
				PrivateKey:     jwtPrivateKey,
				PrivateKeyType: types.PrivateKeyType_RAW,
			})
		}
	} else {
		if !additionalKeys.Empty() {
			// Special case where a new HSM auth server is coming up and has
			// already added local AdditionalTrustedKeys during the standby
			// phase. Keep the existing AdditionalTrustedKeys to avoid
			// invalidating the current Admin identity.
			newKeys = additionalKeys.Clone()
		}
		if !a.keyStore.HasLocalAdditionalKeys(ca) {
			// This auth server has no local AdditionalTrustedKeys in this CA.
			// This is one of 2 cases:
			// 1. There are no AdditionalTrustedKeys at all.
			// 2. There are AdditionalTrustedKeys which were added by a
			//    different auth server.
			// In either case, we need to add newly generated local keys.
			newLocalKeys, err := newKeySet(a.keyStore, ca.GetID())
			if err != nil {
				return trace.Wrap(err)
			}
			newKeys = mergeKeySets(newLocalKeys, newKeys)
		}
	}

	rotation.Started = clock.Now().UTC()
	rotation.GracePeriod = types.NewDuration(gracePeriod)
	rotation.CurrentID = id

	// If no grace period was set, drop old certificate authority without keeping
	// it as trusted.
	//
	// If a grace period was set, in the initial phase of rotation keeps old CAs
	// as primary signing key pairs, and generates new CAs that are trusted, but
	// not used in the cluster.
	if gracePeriod == 0 {
		if err := ca.SetActiveKeys(newKeys); err != nil {
			return trace.Wrap(err)
		}
		// In case of forced rotation, rotation has been started and completed
		// in the same step moving it to standby state.
		rotation.State = types.RotationStateStandby
		rotation.Phase = types.RotationPhaseStandby
	} else {
		if err := ca.SetAdditionalTrustedKeys(newKeys); err != nil {
			return trace.Wrap(err)
		}
		rotation.State = types.RotationStateInProgress
		rotation.Phase = types.RotationPhaseInit
	}

	ca.SetRotation(rotation)
	// The certificate signing algorithm is only set when signing algorithm is
	// explicitly set in the config file. If the config file doesn't set a value,
	// preserve the signing algorithm of the existing CA.
	if req.caSigningAlg != nil {
		sshutils.SetSigningAlgName(ca, *req.caSigningAlg)
	}

	return nil
}

// updateClients swaps old and new CA key sets.
//
// * Old CAs continue to be trusted, but are no longer used for signing.
// * New CAs are used for signing.
// * Remote components will reload with new certificates used for client
//   connections.
func updateClients(ca types.CertAuthority, mode string) error {
	oldActive, oldTrusted := ca.GetActiveKeys(), ca.GetAdditionalTrustedKeys()
	if err := ca.SetActiveKeys(oldTrusted); err != nil {
		return trace.Wrap(err)
	}
	if err := ca.SetAdditionalTrustedKeys(oldActive); err != nil {
		return trace.Wrap(err)
	}

	rotation := ca.GetRotation()
	rotation.State = types.RotationStateInProgress
	rotation.Phase = types.RotationPhaseUpdateClients
	rotation.Mode = mode
	ca.SetRotation(rotation)
	return nil
}

// startRollingBackRotation starts roll back to the original state. Will move
// old CAKeySet back as active.
//
// Will keep the new CAKeySet around as trusted during rollback phase, both
// types of clients may be present in the cluster.
func startRollingBackRotation(ca types.CertAuthority) error {
	rotation := ca.GetRotation()

	// if rolling back from the init phase, active and trusted keys have not yet
	// been swapped
	if rotation.Phase != types.RotationPhaseInit {
		oldActive, oldTrusted := ca.GetActiveKeys(), ca.GetAdditionalTrustedKeys()
		if err := ca.SetActiveKeys(oldTrusted); err != nil {
			return trace.Wrap(err)
		}
		if err := ca.SetAdditionalTrustedKeys(oldActive); err != nil {
			return trace.Wrap(err)
		}
	}

	// Rollback always sets rotation to manual mode.
	rotation.Mode = types.RotationModeManual
	rotation.State = types.RotationStateInProgress
	rotation.Phase = types.RotationPhaseRollback
	ca.SetRotation(rotation)
	return nil
}

// completeRotation completes the certificate authority rotation by removing
// the new CA as trusted.
func completeRotation(clock clockwork.Clock, ca types.CertAuthority) {
	ca.SetAdditionalTrustedKeys(types.CAKeySet{})

	rotation := ca.GetRotation()
	rotation.Started = time.Time{}
	rotation.State = types.RotationStateStandby
	rotation.Phase = types.RotationPhaseStandby
	rotation.LastRotated = clock.Now()
	rotation.Mode = ""
	rotation.Schedule = types.RotationSchedule{}
	ca.SetRotation(rotation)
}
