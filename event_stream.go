package arlo

import (
	"bytes"
	"encoding/json"
	"log"

	"github.com/r3labs/sse"
)

type EventStream struct {
	Registered bool
	Connected  bool
	SSEClient  *sse.Client
	Events     chan *sse.Event

	Verbose bool
}

func NewEventStream() *EventStream {
	return &EventStream{
		Events: make(chan *sse.Event),
	}
}

func (e *EventStream) Listen() error {
	errCh := make(chan error, 1)

	go func() {
		err := e.SSEClient.SubscribeChan("", e.Events)
		if err != nil {
			errCh <- err
		}
	}()

	type eventPayload struct {
		Status string `json:"status"`
	}

	for event := range e.Events {
		e.verbose(string(event.Event))
		e.verbose(string(event.Data))

		if event.Data != nil {
			ep := &eventPayload{}
			b := bytes.NewBuffer(event.Data)
			err := json.NewDecoder(b).Decode(ep)
			if err != nil {
				errCh <- err
				break
			}

			if ep.Status == "connected" {
				e.Connected = true
			}
		}
	}

	return <-errCh
}

func (e *EventStream) verbose(params ...interface{}) {
	if e.Verbose {
		log.Println(params...)
	}
}
