package client

import (
	"context"
	"fmt"
	"net/http"
)

// GetSmartSchedule returns the Autopilot (smart) schedule for the current
// user. Eight Sleep retired the routines/temperature-schedules CRUD API;
// the current app surfaces schedule data as the `smart` subfield of
// GET app-api.8slp.net/v1/users/:id/temperature.
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
	return res.Smart, nil
}
