package reporter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	// "time"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
	"golang.org/x/xerrors"
)

// DiscordWriter sends report to Discord
type DiscordWriter struct {
	Cnf   config.DiscordConf
	Proxy string
}

// Write sends scan results to Discord
func (w DiscordWriter) Write(rs ...models.ScanResult) (err error) {
	for _, r := range rs {
		// Prepare the message
		message := w.prepareMessage(r)

		// Send the message to Discord
		if err := w.sendMessage(message); err != nil {
			return err
		}
	}
	return nil
}

// Prepare the message to be sent to Discord
func (w DiscordWriter) prepareMessage(r models.ScanResult) string {
	// Construct the message content
	message := fmt.Sprintf("**%s**\n%s\n%s\n%s", r.ServerInfo(), r.ScannedCves.FormatCveSummary(), r.ScannedCves.FormatFixedStatus(r.Packages), r.FormatUpdatablePkgsSummary())

	for _, vinfo := range r.ScannedCves {
		maxCvss := vinfo.MaxCvssScore()
		severity := strings.ToUpper(maxCvss.Value.Severity)
		if severity == "" {
			severity = "?"
		}
		// Add vulnerability details to the message
		message += fmt.Sprintf("[%s](https://nvd.nist.gov/vuln/detail/%s) _%s %s %s_\n%s",
			vinfo.CveID, vinfo.CveID, strconv.FormatFloat(maxCvss.Value.Score, 'f', 1, 64),
			severity, maxCvss.Value.Vector, vinfo.Summaries(r.Lang, r.Family)[0].Value)
	}

	return message
}

// Send the message to Discord
func (w DiscordWriter) sendMessage(message string) error {
	// Construct the payload
	payload := map[string]string{
		"content": message,
	}

	// Marshal the payload to JSON
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	// Prepare the HTTP request
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, w.Cnf.WebhookURL, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	// Send the HTTP request
	client, err := util.GetHTTPClient(w.Proxy)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check the response
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return xerrors.Errorf("Failed to send message to Discord: %s", resp.Status)
	}

	return nil
}
