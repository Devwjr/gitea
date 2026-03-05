// Copyright 2024 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package actions

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"code.gitea.io/gitea/modules/json"
	"code.gitea.io/gitea/modules/log"
	"code.gitea.io/gitea/modules/setting"

	"github.com/golang-jwt/jwt/v5"
)

type actionsClaims struct {
	jwt.RegisteredClaims
	Scp    string `json:"scp"`
	TaskID int64
	RunID  int64
	JobID  int64
	Ac     string `json:"ac"`
}

type actionsCacheScope struct {
	Scope      string
	Permission actionsCachePermission
}

type actionsCachePermission int

const (
	actionsCachePermissionRead = 1 << iota
	actionsCachePermissionWrite
)

type TokenPermission struct {
	Contents     actionsCachePermission
	Packages     actionsCachePermission
	Actions      actionsCachePermission
	Deployments  actionsCachePermission
	Pages        actionsCachePermission
	PullRequests actionsCachePermission
	Checks       actionsCachePermission
	Statuses     actionsCachePermission
	Code         actionsCachePermission
	Releases     actionsCachePermission
	Workflows    actionsCachePermission
}

var DefaultTokenPermission = TokenPermission{
	Contents:     actionsCachePermissionWrite,
	Packages:     actionsCachePermissionWrite,
	Actions:      actionsCachePermissionWrite,
	Deployments:  actionsCachePermissionWrite,
	Pages:        actionsCachePermissionWrite,
	PullRequests: actionsCachePermissionWrite,
	Checks:       actionsCachePermissionWrite,
	Statuses:     actionsCachePermissionWrite,
	Code:         actionsCachePermissionWrite,
	Releases:     actionsCachePermissionWrite,
	Workflows:    actionsCachePermissionWrite,
}

var RestrictedTokenPermission = TokenPermission{
	Contents:     actionsCachePermissionRead,
	Packages:     actionsCachePermissionRead,
	Actions:      actionsCachePermissionRead,
	Deployments:  actionsCachePermissionRead,
	Pages:        actionsCachePermissionRead,
	PullRequests: actionsCachePermissionRead,
	Checks:       actionsCachePermissionRead,
	Statuses:     actionsCachePermissionRead,
	Code:         actionsCachePermissionRead,
	Releases:     actionsCachePermissionRead,
	Workflows:    actionsCachePermissionRead,
}

func CreateAuthorizationToken(taskID, runID, jobID int64, perm *TokenPermission) (string, error) {
	if perm == nil {
		perm = &DefaultTokenPermission
	}
	now := time.Now()

	scopes := []actionsCacheScope{
		{Scope: "", Permission: perm.Contents},
		{Scope: "packages", Permission: perm.Packages},
		{Scope: "actions", Permission: perm.Actions},
		{Scope: "deployments", Permission: perm.Deployments},
		{Scope: "pages", Permission: perm.Pages},
		{Scope: "pull-requests", Permission: perm.PullRequests},
		{Scope: "checks", Permission: perm.Checks},
		{Scope: "statuses", Permission: perm.Statuses},
		{Scope: "code", Permission: perm.Code},
		{Scope: "releases", Permission: perm.Releases},
		{Scope: "workflows", Permission: perm.Workflows},
	}

	ac, err := json.Marshal(scopes)
	if err != nil {
		return "", err
	}

	claims := actionsClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(1*time.Hour + setting.Actions.EndlessTaskTimeout)),
			NotBefore: jwt.NewNumericDate(now),
		},
		Scp:    fmt.Sprintf("Actions.Results:%d:%d", runID, jobID),
		Ac:     string(ac),
		TaskID: taskID,
		RunID:  runID,
		JobID:  jobID,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(setting.GetGeneralTokenSigningSecret())
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func ParseAuthorizationToken(req *http.Request) (int64, error) {
	h := req.Header.Get("Authorization")
	if h == "" {
		return 0, nil
	}

	parts := strings.SplitN(h, " ", 2)
	if len(parts) != 2 {
		log.Error("split token failed: %s", h)
		return 0, errors.New("split token failed")
	}

	return TokenToTaskID(parts[1])
}

// TokenToTaskID returns the TaskID associated with the provided JWT token
func TokenToTaskID(token string) (int64, error) {
	parsedToken, err := jwt.ParseWithClaims(token, &actionsClaims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return setting.GetGeneralTokenSigningSecret(), nil
	})
	if err != nil {
		return 0, err
	}

	c, ok := parsedToken.Claims.(*actionsClaims)
	if !parsedToken.Valid || !ok {
		return 0, errors.New("invalid token claim")
	}

	return c.TaskID, nil
}
