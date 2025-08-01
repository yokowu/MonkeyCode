package scan

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"

	"github.com/google/uuid"
)

func Scan(workspace, rule string) (*Result, error) {
	id := uuid.NewString()
	output := fmt.Sprintf("/tmp/%s.json", id)
	cmd := exec.Command(
		"/app/static/sgp/sgp",
		"--metrics=off",
		"--disable-version-check",
		"--disable-nosem",
		"--time",
		"--json",
		"--output", output,
		"--config", rule,
		workspace,
	)
	defer os.Remove(output)

	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	b, err := os.ReadFile(output)
	if err != nil {
		return nil, fmt.Errorf("failed to read output file: %w", err)
	}

	var r Result
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	r.ID = id
	r.Output = string(out)

	return &r, nil
}
