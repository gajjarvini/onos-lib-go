// SPDX-FileCopyrightText: 2020-present Open Networking Foundation <info@opennetworking.org>
//
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"fmt"
	"github.com/golang-jwt/jwt"
	"github.com/grpc-ecosystem/go-grpc-middleware/util/metautils"
	"github.com/onosproject/onos-lib-go/pkg/logging"
        "strings"

	 grpc_auth "github.com/grpc-ecosystem/go-grpc-middleware/auth"
)

const (
	// ContextMetadataTokenKey metadata token key
	ContextMetadataTokenKey = "bearer"
	headerModuleName = "ua"
	// TODO should be an environment variable
	auditTrailModuleName = "audittrail"
)

var (
	log = logging.GetLogger("main")
)

// IfAuditTrailModule returns true if the request is sent by AuditTrail module
func IfAuditTrailModule(ctx context.Context) bool {
	val := metautils.ExtractIncoming(ctx).Get(headerModuleName)
	if val == auditTrailModuleName {
		return true
	}
	return false
}

// AuthenticationInterceptorSAML an interceptor to extract and parse SAML token
// Parsing of token is required only for extracting information like user name,
// group, email etc.
func AuthenticationInterceptorSAML(ctx context.Context) (context.Context, error) {
	// The Audit Trail module does not send token, so skip token parsing
	if IfAuditTrailModule(ctx) {
            log.Debugf("Skipping Interception due to request from Audit Trail Module\n")
            return ctx, nil
	}
	
        // Extract token from metadata in the context
        tokenString, err := grpc_auth.AuthFromMD(ctx, ContextMetadataTokenKey)
	if err != nil {
		log.Errorf("Failed to extract token due to : %v", err)
		return nil, err
	}

	authClaims := jwt.MapClaims{}
	_, _, err = new(jwt.Parser).ParseUnverified(tokenString, authClaims)
	if err != nil {
		log.Errorf("Failed to parse token due to : %v", err)
		return ctx, err
	}

	niceMd := metautils.ExtractIncoming(ctx)
	niceMd.Del("authorization")

        attrMap := authClaims["attr"].(map[string]interface{})

        names, ok := attrMap["http://schemas.microsoft.com/identity/claims/displayname"].([]interface{})
        if ok {
            niceMd.Set("name", names[0].(string))
	}
        emails, ok := attrMap["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"].([]interface{})
        if ok {
		niceMd.Set("email", emails[0].(string))
	}
	if aud, ok := authClaims["aud"]; ok {
		niceMd.Set("aud", aud.(string))
	}
	if exp, ok := authClaims["exp"]; ok {
		niceMd.Set("exp", fmt.Sprintf("%s", exp))
	}
	if iat, ok := authClaims["iat"]; ok {
		niceMd.Set("iat", fmt.Sprintf("%s", iat))
	}
	if iss, ok := authClaims["iss"]; ok {
		niceMd.Set("iss", iss.(string))
	}
	if sub, ok := authClaims["sub"]; ok {
		niceMd.Set("sub", sub.(string))
	}
	if atHash, ok := authClaims["at_hash"]; ok {
		niceMd.Set("at_hash", atHash.(string))
	}
	preferred_names, ok := attrMap["http://schemas.microsoft.com/identity/claims/displayname"].([]interface{})
        if ok {
		niceMd.Set("preferred_username", preferred_names[0].(string))
	}

	groupsIf, ok := attrMap["http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"].([]interface{})
	if ok {
		groups := make([]string, 0)
		for _, g := range groupsIf {
			groups = append(groups, g.(string))
		}
		niceMd.Set("groups", strings.Join(groups, ";"))
	}
	rolesIf, ok := authClaims["roles"].([]interface{})
	if ok {
		roles := make([]string, 0)
		for _, r := range rolesIf {
			roles = append(roles, r.(string))
		}
		niceMd.Set("roles", strings.Join(roles, ";"))
	}

	return niceMd.ToIncoming(ctx), nil
}

// AuthenticationInterceptor an interceptor for OAuth2.0 authentication
func AuthenticationInterceptor(ctx context.Context) (context.Context, error) {
	// Extract token from metadata in the context
	tokenString, err := grpc_auth.AuthFromMD(ctx, ContextMetadataTokenKey)
	if err != nil {
		return nil, err
	}

	// Authenticate the jwt token
	jwtAuth := new(auth.JwtAuthenticator)
	authClaims, err := jwtAuth.ParseAndValidate(tokenString)
	if err != nil {
		return ctx, err
	}

	niceMd := metautils.ExtractIncoming(ctx)
	niceMd.Del("authorization")
	if name, ok := authClaims["name"]; ok {
		niceMd.Set("name", name.(string))
	}
	if email, ok := authClaims["email"]; ok {
		niceMd.Set("email", email.(string))
	}
	if aud, ok := authClaims["aud"]; ok {
		niceMd.Set("aud", aud.(string))
	}
	if exp, ok := authClaims["exp"]; ok {
		niceMd.Set("exp", fmt.Sprintf("%s", exp))
	}
	if iat, ok := authClaims["iat"]; ok {
		niceMd.Set("iat", fmt.Sprintf("%s", iat))
	}
	if iss, ok := authClaims["iss"]; ok {
		niceMd.Set("iss", iss.(string))
	}
	if sub, ok := authClaims["sub"]; ok {
		niceMd.Set("sub", sub.(string))
	}
	if atHash, ok := authClaims["at_hash"]; ok {
		niceMd.Set("at_hash", atHash.(string))
	}
	if preferred, ok := authClaims["preferred_username"]; ok {
		niceMd.Set("preferred_username", preferred.(string))
	}

	groupsIf, ok := authClaims["groups"].([]interface{})
	if ok {
		groups := make([]string, 0)
		for _, g := range groupsIf {
			groups = append(groups, g.(string))
		}
		niceMd.Set("groups", strings.Join(groups, ";"))
	}
	rolesIf, ok := authClaims["roles"].([]interface{})
	if ok {
		roles := make([]string, 0)
		for _, r := range rolesIf {
			roles = append(roles, r.(string))
		}
		niceMd.Set("roles", strings.Join(roles, ";"))
	}
	return niceMd.ToIncoming(ctx), nil
}
