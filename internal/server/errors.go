package server

import (
	"net/http"
	"strings"

	"github.com/jkaninda/certio/internal/server/dto"
	"github.com/jkaninda/okapi"
)

// errorHandler reshapes the aborts okapi raises on its own — a failed bind, a
// failed validation, a router 404 — into the same dto.ErrorResponse the
// handlers return.
//
// Without it the API would speak two error dialects: okapi's
// {code, message, details, timestamp} for anything rejected before a handler
// runs, and Certio's {error, message} for everything after. The dashboard
// branches on the machine-readable `error` code, so a bind failure would
// arrive as an unrecognised shape carrying only "Bad Request" while the
// sentence that says which field is wrong sat in a field nothing reads.
func errorHandler(c *okapi.Context, code int, message string, err error) error {
	// okapi puts the readable half in err and a generic label in message; for
	// a validation failure the err is the part worth showing.
	detail := message
	if err != nil {
		detail = bindMessage(err.Error())
	}

	return c.JSON(code, dto.ErrorResponse{
		Error:   errorCode(code),
		Message: detail,
	})
}

// errorCode maps a status onto the stable string the dashboard branches on.
// These match what the handlers emit for the same conditions.
func errorCode(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "invalid_request"
	case http.StatusUnauthorized:
		return "unauthorized"
	case http.StatusForbidden:
		return "forbidden"
	case http.StatusNotFound:
		return "not_found"
	case http.StatusConflict:
		return "conflict"
	case http.StatusTooManyRequests:
		return "rate_limited"
	default:
		if status >= http.StatusInternalServerError {
			return "internal_error"
		}
		return "request_failed"
	}
}

// bindMessage strips okapi's internal framing so the reply names the field
// rather than the plumbing that noticed it.
func bindMessage(msg string) string {
	for _, prefix := range []string{
		"failed to bind body: ",
		"failed to bind request: ",
		"binding error: ",
		"bind error for ",
	} {
		msg = strings.TrimPrefix(msg, prefix)
	}
	return msg
}
