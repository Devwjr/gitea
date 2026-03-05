// Copyright 2022 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package actions

import (
	"context"
	"errors"
	"fmt"

	actions_model "code.gitea.io/gitea/models/actions"
	"code.gitea.io/gitea/models/db"
	repo_model "code.gitea.io/gitea/models/repo"
	secret_model "code.gitea.io/gitea/models/secret"
	unit_model "code.gitea.io/gitea/models/unit"
	notify_service "code.gitea.io/gitea/services/notify"

	runnerv1 "code.gitea.io/actions-proto-go/runner/v1"
	"go.yaml.in/yaml/v4"
	"google.golang.org/protobuf/types/known/structpb"
)

func PickTask(ctx context.Context, runner *actions_model.ActionRunner) (*runnerv1.Task, bool, error) {
	var (
		task       *runnerv1.Task
		job        *actions_model.ActionRunJob
		actionTask *actions_model.ActionTask
	)

	if runner.Ephemeral {
		var task actions_model.ActionTask
		has, err := db.GetEngine(ctx).Where("runner_id = ?", runner.ID).Get(&task)
		// Let the runner retry the request, do not allow to proceed
		if err != nil {
			return nil, false, err
		}
		if has {
			if task.Status == actions_model.StatusWaiting || task.Status == actions_model.StatusRunning || task.Status == actions_model.StatusBlocked {
				return nil, false, nil
			}
			// task has been finished, remove it
			_, err = db.DeleteByID[actions_model.ActionRunner](ctx, runner.ID)
			if err != nil {
				return nil, false, err
			}
			return nil, false, errors.New("runner has been removed")
		}
	}

	if err := db.WithTx(ctx, func(ctx context.Context) error {
		t, ok, err := actions_model.CreateTaskForRunner(ctx, runner)
		if err != nil {
			return fmt.Errorf("CreateTaskForRunner: %w", err)
		}
		if !ok {
			return nil
		}

		if err := t.LoadAttributes(ctx); err != nil {
			return fmt.Errorf("task LoadAttributes: %w", err)
		}
		job = t.Job
		actionTask = t

		secrets, err := secret_model.GetSecretsOfTask(ctx, t)
		if err != nil {
			return fmt.Errorf("GetSecretsOfTask: %w", err)
		}

		vars, err := actions_model.GetVariablesOfRun(ctx, t.Job.Run)
		if err != nil {
			return fmt.Errorf("GetVariablesOfRun: %w", err)
		}

		needs, err := findTaskNeeds(ctx, job)
		if err != nil {
			return fmt.Errorf("findTaskNeeds: %w", err)
		}

		taskContext, err := generateTaskContext(ctx, t)
		if err != nil {
			return fmt.Errorf("generateTaskContext: %w", err)
		}

		task = &runnerv1.Task{
			Id:              t.ID,
			WorkflowPayload: t.Job.WorkflowPayload,
			Context:         taskContext,
			Secrets:         secrets,
			Vars:            vars,
			Needs:           needs,
		}

		return nil
	}); err != nil {
		return nil, false, err
	}

	if task == nil {
		return nil, false, nil
	}

	CreateCommitStatusForRunJobs(ctx, job.Run, job)
	notify_service.WorkflowJobStatusUpdate(ctx, job.Run.Repo, job.Run.TriggerUser, job, actionTask)

	return task, true, nil
}

func generateTaskContext(ctx context.Context, t *actions_model.ActionTask) (*structpb.Struct, error) {
	perm := calculateTokenPermission(ctx, t)
	giteaRuntimeToken, err := CreateAuthorizationToken(t.ID, t.Job.RunID, t.JobID, perm)
	if err != nil {
		return nil, err
	}

	gitCtx := GenerateGiteaContext(t.Job.Run, t.Job)
	gitCtx["token"] = t.Token
	gitCtx["gitea_runtime_token"] = giteaRuntimeToken

	return structpb.NewStruct(gitCtx)
}

func calculateTokenPermission(ctx context.Context, t *actions_model.ActionTask) *TokenPermission {
	repo := t.Job.Run.Repo
	if repo == nil {
		return &DefaultTokenPermission
	}

	unit, err := repo.GetUnit(ctx, unit_model.TypeActions)
	if err != nil || unit == nil {
		return &DefaultTokenPermission
	}

	cfg := unit.ActionsConfig()
	maxPerm := cfg.GetMaxActionsTokenPermission()

	if t.IsForkPullRequest {
		return &RestrictedTokenPermission
	}

	workflowPerm := getWorkflowPermissions(t.Job)

	perm := clampPermission(workflowPerm, maxPerm)

	if cfg.AllowCrossRepositoryActionsToken && !repo.IsPrivate {
		return perm
	}

	return perm
}

func getWorkflowPermissions(job *actions_model.ActionRunJob) *TokenPermission {
	parsedJob, err := job.ParseJob()
	if err != nil || parsedJob == nil {
		return &DefaultTokenPermission
	}

	perm := &DefaultTokenPermission

	if parsedJob.RawPermissions.Kind != 0 {
		perm = parsePermissionsFromYAML(&parsedJob.RawPermissions)
	}

	return perm
}

func parsePermissionsFromYAML(node *yaml.Node) *TokenPermission {
	perm := &DefaultTokenPermission

	if node == nil || node.Kind != yaml.MappingNode {
		return perm
	}

	for i := 0; i < len(node.Content); i += 2 {
		key := node.Content[i].Value
		value := node.Content[i+1].Value

		switch key {
		case "contents":
			if value == "read" {
				perm.Contents = actionsCachePermissionRead
			} else if value == "write" {
				perm.Contents = actionsCachePermissionWrite
			}
		case "packages":
			if value == "read" {
				perm.Packages = actionsCachePermissionRead
			} else if value == "write" {
				perm.Packages = actionsCachePermissionWrite
			}
		case "actions":
			if value == "read" {
				perm.Actions = actionsCachePermissionRead
			} else if value == "write" {
				perm.Actions = actionsCachePermissionWrite
			}
		case "deployments":
			if value == "read" {
				perm.Deployments = actionsCachePermissionRead
			} else if value == "write" {
				perm.Deployments = actionsCachePermissionWrite
			}
		case "pages":
			if value == "read" {
				perm.Pages = actionsCachePermissionRead
			} else if value == "write" {
				perm.Pages = actionsCachePermissionWrite
			}
		case "pull-requests":
			if value == "read" {
				perm.PullRequests = actionsCachePermissionRead
			} else if value == "write" {
				perm.PullRequests = actionsCachePermissionWrite
			}
		case "checks":
			if value == "read" {
				perm.Checks = actionsCachePermissionRead
			} else if value == "write" {
				perm.Checks = actionsCachePermissionWrite
			}
		case "statuses":
			if value == "read" {
				perm.Statuses = actionsCachePermissionRead
			} else if value == "write" {
				perm.Statuses = actionsCachePermissionWrite
			}
		case "code":
			if value == "read" {
				perm.Code = actionsCachePermissionRead
			} else if value == "write" {
				perm.Code = actionsCachePermissionWrite
			}
		case "releases":
			if value == "read" {
				perm.Releases = actionsCachePermissionRead
			} else if value == "write" {
				perm.Releases = actionsCachePermissionWrite
			}
		case "workflows":
			if value == "read" {
				perm.Workflows = actionsCachePermissionRead
			} else if value == "write" {
				perm.Workflows = actionsCachePermissionWrite
			}
		}
	}

	return perm
}

func clampPermission(workflowPerm *TokenPermission, maxLevel repo_model.ActionsTokenPermissionLevel) *TokenPermission {
	if maxLevel == repo_model.ActionsTokenPermissionPermissive {
		return workflowPerm
	}

	restricted := &RestrictedTokenPermission

	return &TokenPermission{
		Contents:     clampSinglePermission(workflowPerm.Contents, restricted.Contents),
		Packages:     clampSinglePermission(workflowPerm.Packages, restricted.Packages),
		Actions:      clampSinglePermission(workflowPerm.Actions, restricted.Actions),
		Deployments:  clampSinglePermission(workflowPerm.Deployments, restricted.Deployments),
		Pages:        clampSinglePermission(workflowPerm.Pages, restricted.Pages),
		PullRequests: clampSinglePermission(workflowPerm.PullRequests, restricted.PullRequests),
		Checks:       clampSinglePermission(workflowPerm.Checks, restricted.Checks),
		Statuses:     clampSinglePermission(workflowPerm.Statuses, restricted.Statuses),
		Code:         clampSinglePermission(workflowPerm.Code, restricted.Code),
		Releases:     clampSinglePermission(workflowPerm.Releases, restricted.Releases),
		Workflows:    clampSinglePermission(workflowPerm.Workflows, restricted.Workflows),
	}
}

func clampSinglePermission(perm, max actionsCachePermission) actionsCachePermission {
	if perm > max {
		return max
	}
	return perm
}

func findTaskNeeds(ctx context.Context, taskJob *actions_model.ActionRunJob) (map[string]*runnerv1.TaskNeed, error) {
	taskNeeds, err := FindTaskNeeds(ctx, taskJob)
	if err != nil {
		return nil, err
	}
	ret := make(map[string]*runnerv1.TaskNeed, len(taskNeeds))
	for jobID, taskNeed := range taskNeeds {
		ret[jobID] = &runnerv1.TaskNeed{
			Outputs: taskNeed.Outputs,
			Result:  runnerv1.Result(taskNeed.Result),
		}
	}
	return ret, nil
}
