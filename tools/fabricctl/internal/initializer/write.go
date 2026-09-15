// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package initializer

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/singleaxis/singleaxis-fabric/tools/fabricctl/internal/bundle"
)

type targetPaths struct {
	directory, deployment, target, values, secrets, plan, manifest string
}

func writeBundleArtifacts(paths targetPaths, artifacts []bundle.Artifact) (targetPaths, error) {
	return writeBundleArtifactsWithCreate(paths, artifacts, createFinal)
}

// WriteBundle commits an already validated offline bundle using the same
// restrictive, no-clobber, all-or-nothing path as the interactive wizard.
func WriteBundle(outputDir string, built bundle.Bundle) ([]string, error) {
	paths, err := writeBundleArtifacts(outputPaths(outputDir), built.Artifacts)
	if err != nil {
		return nil, err
	}
	return []string{paths.deployment, paths.target, paths.values, paths.secrets, paths.plan, paths.manifest}, nil
}

func writeBundleArtifactsWithCreate(paths targetPaths, artifacts []bundle.Artifact, create func(string, []byte) error) (targetPaths, error) {
	canonicalDirectory, err := canonicalizeDirectory(paths.directory)
	if err != nil {
		return targetPaths{}, err
	}
	paths = outputPaths(canonicalDirectory)
	if err := prepareOutputDirectory(paths.directory); err != nil {
		return targetPaths{}, err
	}
	if err := inspectTargets(paths); err != nil {
		return targetPaths{}, err
	}

	allowed := map[string]string{
		bundle.DeploymentFileName:       paths.deployment,
		bundle.InstallTargetFileName:    paths.target,
		bundle.ValuesFileName:           paths.values,
		bundle.SecretsRequiredFileName:  paths.secrets,
		bundle.InstallationPlanFileName: paths.plan,
		bundle.ManifestFileName:         paths.manifest,
	}
	if len(artifacts) != len(allowed) {
		return targetPaths{}, fmt.Errorf("offline bundle must contain exactly six allowlisted artifacts")
	}
	created := make([]string, 0, len(artifacts))
	rollback := func(primary error) error {
		result := primary
		for index := len(created) - 1; index >= 0; index-- {
			if removeErr := os.Remove(created[index]); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				result = errors.Join(result, fmt.Errorf("roll back newly created bundle artifact: %w", removeErr))
			}
		}
		return result
	}
	seen := make(map[string]bool, len(artifacts))
	for _, artifact := range artifacts {
		path, ok := allowed[artifact.Path]
		if !ok || seen[artifact.Path] {
			return targetPaths{}, rollback(fmt.Errorf("offline bundle contains an unexpected or duplicate artifact"))
		}
		seen[artifact.Path] = true
		if err := create(path, artifact.Payload); err != nil {
			return targetPaths{}, rollback(err)
		}
		created = append(created, path)
	}
	return paths, nil
}

// canonicalizeDirectory resolves the longest existing prefix once and then
// operates on the resulting canonical path. This permits OS-managed prefixes
// such as macOS /var -> /private/var without reopening the supplied symlink
// path during commit.
func canonicalizeDirectory(directory string) (string, error) {
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return "", fmt.Errorf("resolve output path: %w", err)
	}
	existing := absolute
	missing := make([]string, 0)
	for {
		_, statErr := os.Lstat(existing)
		if statErr == nil {
			break
		}
		if !errors.Is(statErr, os.ErrNotExist) {
			return "", fmt.Errorf("inspect output path component %s: %w", existing, statErr)
		}
		parent := filepath.Dir(existing)
		if parent == existing {
			return "", fmt.Errorf("find existing output path prefix: %s", absolute)
		}
		missing = append(missing, filepath.Base(existing))
		existing = parent
	}
	canonical, err := filepath.EvalSymlinks(existing)
	if err != nil {
		return "", fmt.Errorf("canonicalize output path prefix %s: %w", existing, err)
	}
	for index := len(missing) - 1; index >= 0; index-- {
		canonical = filepath.Join(canonical, missing[index])
	}
	return canonical, nil
}

func prepareOutputDirectory(directory string) error {
	if err := rejectSymlinkComponents(directory); err != nil {
		return err
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	if err := rejectSymlinkComponents(directory); err != nil {
		return err
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return fmt.Errorf("inspect output directory: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("output path is not a directory: %s", directory)
	}
	return nil
}

func rejectSymlinkComponents(path string) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve output path: %w", err)
	}
	volume := filepath.VolumeName(absolute)
	root := volume + string(os.PathSeparator)
	remainder := strings.TrimPrefix(absolute, root)
	current := root
	for _, component := range strings.Split(remainder, string(os.PathSeparator)) {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, statErr := os.Lstat(current)
		if errors.Is(statErr, os.ErrNotExist) {
			return nil
		}
		if statErr != nil {
			return fmt.Errorf("inspect output path component %s: %w", current, statErr)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: output path component %s", ErrSymlinkTarget, current)
		}
	}
	return nil
}

func inspectTargets(paths targetPaths) error {
	for _, target := range []string{paths.deployment, paths.target, paths.values, paths.secrets, paths.plan, paths.manifest} {
		info, err := os.Lstat(target)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect initializer target: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: %s", ErrSymlinkTarget, target)
		}
		return fmt.Errorf("%w: %s", ErrTargetExists, target)
	}
	return nil
}

func createFinal(path string, payload []byte) (returnErr error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%w: %s", ErrTargetExists, path)
		}
		return fmt.Errorf("create initializer target %s: %w", path, err)
	}
	remove := true
	closed := false
	defer func() {
		if !closed {
			if closeErr := file.Close(); returnErr == nil && closeErr != nil {
				returnErr = fmt.Errorf("close initializer target %s: %w", path, closeErr)
			}
		}
		if returnErr != nil && remove {
			if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				returnErr = errors.Join(returnErr, fmt.Errorf("roll back incomplete initializer target %s: %w", path, removeErr))
			}
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return fmt.Errorf("secure initializer target %s: %w", path, err)
	}
	if _, err := file.Write(payload); err != nil {
		return fmt.Errorf("write initializer target %s: %w", path, err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync initializer target %s: %w", path, err)
	}
	if err := file.Close(); err != nil {
		closed = true
		return fmt.Errorf("close initializer target %s: %w", path, err)
	}
	closed = true
	remove = false
	return nil
}
