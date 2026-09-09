package authorizationslog

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"
	"time"

	authorization "github.com/faustbrian/go-authorization"
)

func TestInstrumenterBeginWritesRepeatableBoundedEvents(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	instrumenter, err := New(slog.New(slog.NewJSONHandler(&output, nil)), slog.LevelInfo)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	next, finish := instrumenter.Begin(ctx)
	if next != ctx {
		t.Error("Begin changed context")
	}
	event := authorization.Event{
		Outcome: authorization.Allow, Reason: "acl-allow", Revision: 7,
		MatchedPolicyIDs: []authorization.PolicyID{"entry-1"}, MatchedPolicyIDsTruncated: true,
		TraceCount: 2, TraceTruncated: true, Duration: 1500 * time.Microsecond,
	}
	finish(event)
	finish(event)
	decoder := json.NewDecoder(&output)
	for index := 0; index < 2; index++ {
		var record map[string]any
		if err := decoder.Decode(&record); err != nil {
			t.Fatal(err)
		}
		if record["msg"] != "authorization decision" || record["outcome"] != "allow" ||
			record["reason"] != "acl-allow" || record["revision"] != float64(7) ||
			record["duration_ms"] != 1.5 || record["failed"] != false {
			t.Errorf("record = %#v", record)
		}
	}
	next, finish = instrumenter.Start(ctx)
	if next != ctx || finish == nil {
		t.Fatal("Start did not delegate to Begin")
	}
}

func TestNewRejectsNilLogger(t *testing.T) {
	t.Parallel()
	if _, err := New(nil, slog.LevelInfo); !errors.Is(err, ErrNilLogger) {
		t.Fatalf("New(nil) error = %v", err)
	}
}
