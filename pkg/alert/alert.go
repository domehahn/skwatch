package alert

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/domehahn/skwatch/pkg/vuln"
)

type Notification struct {
	Timestamp time.Time      `json:"timestamp"`
	Target    string         `json:"target"`
	Findings  []vuln.Finding `json:"findings"`
	Summary   string         `json:"summary"`
}

func DispatchWebhook(url string, notif *Notification) error {
	payload, err := json.Marshal(notif)
	if err != nil {
		return err
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook responded with HTTP %d", resp.StatusCode)
	}
	return nil
}
