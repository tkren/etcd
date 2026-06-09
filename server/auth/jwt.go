// Copyright 2017 The etcd Authors
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

package auth

import (
	"context"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

type tokenJWT struct {
	lg         *zap.Logger
	signMethod jwt.SigningMethod
	key        any
	ttl        time.Duration
	keyFunc    jwt.Keyfunc
	parser     *jwt.Parser
}

func (t *tokenJWT) enable()                         {}
func (t *tokenJWT) disable()                        {}
func (t *tokenJWT) invalidateUser(string)           {}
func (t *tokenJWT) genTokenPrefix() (string, error) { return "", nil }
func (t *tokenJWT) verifyOnly() bool { return t.key == nil }

func (t *tokenJWT) info(ctx context.Context, token string, rev uint64) (*AuthInfo, bool) {
	// rev isn't used in JWT, it is only used in simple token
	var (
		username string
		revision float64
	)

	parsed, err := t.parser.Parse(token, t.keyFunc)
	if err != nil {
		t.lg.Warn(
			"failed to parse a JWT token",
			zap.Error(err),
		)
		return nil, false
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !parsed.Valid || !ok {
		t.lg.Warn("failed to obtain claims from a JWT token")
		return nil, false
	}

	username, ok = claims["username"].(string)
	if !ok {
		t.lg.Warn("failed to obtain user claims from jwt token")
		return nil, false
	}

	revision, ok = claims["revision"].(float64)
	if !ok {
		t.lg.Warn("failed to obtain revision claims from jwt token")
		return nil, false
	}

	return &AuthInfo{Username: username, Revision: uint64(revision)}, true
}

func (t *tokenJWT) assign(ctx context.Context, username string, revision uint64) (string, error) {
	if t.verifyOnly() {
		return "", ErrVerifyOnly
	}

	// Future work: let a jwt token include permission information would be useful for
	// permission checking in proxy side.
	tk := jwt.NewWithClaims(t.signMethod,
		jwt.MapClaims{
			"username": username,
			"revision": revision,
			"exp":      time.Now().Add(t.ttl).Unix(),
		})

	token, err := tk.SignedString(t.key)
	if err != nil {
		t.lg.Debug(
			"failed to sign a JWT token",
			zap.String("user-name", username),
			zap.Uint64("revision", revision),
			zap.Error(err),
		)
		return "", err
	}

	if ce := t.lg.Check(zap.DebugLevel, "created/assigned a new JWT token"); ce != nil {
		tokenFingerprint := redactToken(token)
		ce.Write(zap.String("user-name", username),
			zap.Uint64("revision", revision),
			zap.String("token-fingerprint", tokenFingerprint))
	}
	return token, nil
}

// newTokenProviderJWT builds a JWT token provider from at least one option group. We distinguish between:
// - signing group, defining priv-key, sign-method, and (optional) pub-key; and
// - verify-only group, defining pub-key and sign-method, but no priv-key.
// Only one signing group is allowed to be defined, and if all option groups are verify-only, the provider will be verify-only.
func newTokenProviderJWT(lg *zap.Logger, optGroups []map[string]string) (*tokenJWT, error) {
	if lg == nil {
		lg = zap.NewNop()
	}
	if len(optGroups) == 0 {
		lg.Error("no JWT options provided")
		return nil, ErrInvalidAuthOpts
	}

	// start with the empty token provider and fill in fields as we parse option groups
	t := &tokenJWT{lg: lg}
	verifyOnly := true

	var verifyKeys []jwt.VerificationKey
	var validMethods []string

	for _, optMap := range optGroups {
		var err error
		var opts jwtOptions
		err = opts.ParseWithDefaults(optMap)
		if err != nil {
			lg.Error("problem loading JWT options", zap.Error(err))
			return nil, ErrInvalidAuthOpts
		}

		keys := make([]string, 0, len(optMap))
		for k := range optMap {
			if !knownOptions[k] {
				keys = append(keys, k)
			}
		}
		if len(keys) > 0 {
			lg.Warn("unknown JWT options", zap.Strings("keys", keys))
		}

		// get a pair of signing key and verification key
		signKey, verifyKey, err := opts.keyPair()
		if err != nil {
			return nil, err
		}

		// we found a verify-only group: trust verification key and add sign-method
		if signKey == nil {
			verifyKeys = append(verifyKeys, verifyKey)
			validMethods = append(validMethods, opts.SignMethod.Alg())
			continue
		}

		// only one signing group is allowed across all option groups
		if !verifyOnly {
			lg.Error("multiple JWT signing keys provided")
			return nil, ErrInvalidAuthOpts
		}
		verifyOnly = false

		// we found the signing group
		t.key = signKey
		t.signMethod = opts.SignMethod
		t.ttl = opts.TTL

		// the signing group's verification key and sign-method is always the first key and valid method, resp.
		verifyKeys = append([]jwt.VerificationKey{verifyKey}, verifyKeys...)
		validMethods = append([]string{opts.SignMethod.Alg()}, validMethods...)
	}

	// we always trust one or more verification keys
	t.keyFunc = func(token *jwt.Token) (any, error) {
		return jwt.VerificationKeySet{Keys: verifyKeys}, nil
	}
	// JWT parser trusting only valid methods corresponding to trusted verification keys
	t.parser = jwt.NewParser(jwt.WithValidMethods(validMethods))

	return t, nil
}
