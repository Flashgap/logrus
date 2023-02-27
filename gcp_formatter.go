package logrus

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const (
	FieldKeyRequest        = "request"
	FieldKeyResponseStatus = "responseStatus"
	FieldKeyResponseSize   = "responseSize"
	FieldKeyStartAt        = "startAt"
	FieldKeyTrace          = "trace"
	FieldKeySpan           = "span"
	FieldKeyOperation      = "operation"
	FieldKeyRemoteIP       = "remoteIP"
	FieldKeyFullPath       = "fullPath"
	FieldKeyAuthIsAdmin    = "authIsAdmin"
	FieldKeyAuthProvider   = "authProvider"
	FieldKeyAuthUserID     = "authUserID"
	FieldKeyAuthEmail      = "authEmail"
	FieldKeyAppVersion     = "appVersion"
	FieldKeyDeviceOS       = "deviceOS"
	FieldKeyTestName       = "testName"
)

type GCPFormatter struct {
	GoogleProjectID string
}

func (f *GCPFormatter) Format(entry *Entry) ([]byte, error) {
	data := make(Fields)
	data["severity"] = levelToGCPSeverity(entry.Level)
	data["message"] = entry.Message
	data["time"] = entry.Time.Format(time.RFC3339Nano)

	// All contextual info stored in the entry
	if entry.Context != nil {
		if prefix := entry.Context.Value(FieldKeyPrefix); prefix != nil {
			data["message"] = prefix.(string) + " " + data["message"].(string)
		}

		// All HTTP info stored in the entry
		httpRequest := make(map[string]interface{})
		if reqI := entry.Context.Value(FieldKeyRequest); reqI != nil {
			req := reqI.(*http.Request)
			httpRequest["requestMethod"] = req.Method
			httpRequest["requestUrl"] = req.URL.String()
			httpRequest["requestSize"] = req.ContentLength
			httpRequest["userAgent"] = req.UserAgent()
			httpRequest["referer"] = req.Referer()
			httpRequest["protocol"] = req.Proto
		}
		if ripI := entry.Context.Value(FieldKeyRemoteIP); ripI != nil {
			rIP := ripI.(string)
			httpRequest["remoteIp"] = rIP
		}
		if respI := entry.Context.Value(FieldKeyResponseStatus); respI != nil {
			resp := respI.(int)
			httpRequest["status"] = resp
			if respSizeI := entry.Context.Value(FieldKeyResponseSize); respSizeI != nil {
				respSize := respSizeI.(int)
				httpRequest["responseSize"] = respSize
			}
			if startAtI := entry.Context.Value(FieldKeyStartAt); startAtI != nil {
				dur := time.Since(startAtI.(time.Time))
				httpRequest["latency"] = fmt.Sprintf("%.9fs", float64(dur)/float64(time.Second))
			}
		}
		if len(httpRequest) > 0 {
			data["httpRequest"] = httpRequest
		}

		// All Google Tracing info stored in the entry
		if traceI := entry.Context.Value(FieldKeyTrace); traceI != nil {
			data["logging.googleapis.com/trace"] = fmt.Sprintf("projects/%s/traces/%s", f.GoogleProjectID, traceI.(string))
			if spanI := entry.Context.Value(FieldKeySpan); spanI != nil {
				data["logging.googleapis.com/spanId"] = spanI.(string)
			}
		}

		// All Operation info stored in the entry
		if opI := entry.Context.Value(FieldKeyOperation); opI != nil {
			data["logging.googleapis.com/operation"] = opI.(map[string]interface{})
		}

		// Info about the authentication of the call
		jsonPayload := make(Fields)
		if authI := entry.Context.Value(FieldKeyAuthProvider); authI != nil {
			authProvider := authI.(string)
			jsonPayload["auth_provider"] = authProvider
			if authEmailI := entry.Context.Value(FieldKeyAuthEmail); authEmailI != nil {
				authEmail := authEmailI.(string)
				jsonPayload["auth_email"] = authEmail
			}
			if authIsAdminI := entry.Context.Value(FieldKeyAuthIsAdmin); authIsAdminI != nil {
				authIsAdmin := authIsAdminI.(bool)
				jsonPayload["auth_is_admin"] = authIsAdmin
			}
			if authUserIDI := entry.Context.Value(FieldKeyAuthUserID); authUserIDI != nil {
				authUserID := authUserIDI.(string)
				jsonPayload["auth_user_id"] = authUserID
			}
		}
		if appVersion := entry.Context.Value(FieldKeyAppVersion); appVersion != nil {
			jsonPayload["app_version"] = appVersion.(string)
		}
		if deviceOS := entry.Context.Value(FieldKeyDeviceOS); deviceOS != nil {
			jsonPayload["device_os"] = deviceOS.(string)
		}
		if len(jsonPayload) > 0 {
			data["labels"] = jsonPayload
		}
	}

	b, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal fields to JSON, %w", err)
	}
	return append(b, '\n'), nil

}

// https://cloud.google.com/logging/docs/reference/v2/rest/v2/LogEntry#LogSeverity
func levelToGCPSeverity(level Level) string {
	switch level {
	case TraceLevel:
		return "trace"
	case DebugLevel:
		return "debug"
	case InfoLevel:
		return "info"
	case WarnLevel:
		return "warning"
	case ErrorLevel:
		return "error"
	case CriticalLevel:
		return "critical"
	case FatalLevel:
		return "alert"
	case PanicLevel:
		return "emergency"
	default:
		return "error"
	}
}
