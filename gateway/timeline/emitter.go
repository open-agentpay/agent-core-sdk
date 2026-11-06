package timeline

import (
	"context"
	"log/slog"

	"github.com/agent-core-sdk/gateway/agent"
)

// TimelineAuditEmitter wraps a timeline.Service as an agent.AuditEmitter.
type TimelineAuditEmitter struct {
	timelineSvc Service
	underlying  agent.AuditEmitter
}

// NewTimelineAuditEmitter creates an emitter that feeds both the timeline read model and an optional underlying emitter.
func NewTimelineAuditEmitter(timelineSvc Service, underlying agent.AuditEmitter) *TimelineAuditEmitter {
	return &TimelineAuditEmitter{
		timelineSvc: timelineSvc,
		underlying:  underlying,
	}
}

// Emit records the audit event into the timeline service and forwards to any underlying emitter.
func (e *TimelineAuditEmitter) Emit(event *agent.AuditEvent) {
	if event == nil {
		return
	}
	if e.timelineSvc != nil {
		if err := e.timelineSvc.RecordEvent(context.Background(), event); err != nil {
			slog.Error("failed to record timeline event", slog.String("event_id", event.EventID), slog.Any("error", err))
		}
	}
	if e.underlying != nil {
		e.underlying.Emit(event)
	}
}
