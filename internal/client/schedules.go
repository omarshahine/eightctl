package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
)

// ErrNoSmartSchedule is returned when the user has no Autopilot schedule
// configured (server omits or nulls the `smart` field).
var ErrNoSmartSchedule = errors.New("no Autopilot schedule configured")

// GetSmartSchedule returns the `smart` subfield of the app-api temperature
// resource (the Autopilot schedule).
func (c *Client) GetSmartSchedule(ctx context.Context) (map[string]any, error) {
	if err := c.requireUser(ctx); err != nil {
		return nil, err
	}
	u := fmt.Sprintf("%s/users/%s/temperature", appAPIBaseURL, c.UserID)
	var res struct {
		Smart map[string]any `json:"smart"`
	}
	if err := c.doURL(ctx, http.MethodGet, u, nil, &res); err != nil {
		return nil, err
	}
	if res.Smart == nil {
		return nil, ErrNoSmartSchedule
	}
	return res.Smart, nil
}
