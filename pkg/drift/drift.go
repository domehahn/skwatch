package drift

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
)

type DriftReport struct {
	Path           string   `json:"path"`
	ExpectedDigest string   `json:"expected_digest"`
	ActualDigest   string   `json:"actual_digest"`
	HasDrift       bool     `json:"has_drift"`
	ModifiedFiles  []string `json:"modified_files,omitempty"`
}

func ComputeDirectoryDigest(dirPath string) (string, error) {
	hasher := sha256.New()
	var fileList []string

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			rel, _ := filepath.Rel(dirPath, path)
			fileList = append(fileList, rel)
		}
		return nil
	})
	if err != nil {
		return "", err
	}

	sort.Strings(fileList)

	for _, rel := range fileList {
		fullPath := filepath.Join(dirPath, rel)
		f, err := os.Open(fullPath)
		if err != nil {
			return "", err
		}
		defer f.Close()

		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			return "", err
		}
		fileHash := hex.EncodeToString(h.Sum(nil))
		hasher.Write([]byte(fmt.Sprintf("%s:%s\n", rel, fileHash)))
	}

	return "sha256:" + hex.EncodeToString(hasher.Sum(nil)), nil
}

func CheckDrift(dirPath, expectedDigest string) (*DriftReport, error) {
	actual, err := ComputeDirectoryDigest(dirPath)
	if err != nil {
		return nil, err
	}

	return &DriftReport{
		Path:           dirPath,
		ExpectedDigest: expectedDigest,
		ActualDigest:   actual,
		HasDrift:       expectedDigest != "" && expectedDigest != actual,
	}, nil
}
