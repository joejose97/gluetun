package httpproxy

import (
	"context"
	"errors"
	"fmt"

	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/models"
)

func (s *state) setStatusWithLock(status models.LoopStatus) {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	s.status = status
}

func (l *looper) GetStatus() (status models.LoopStatus) {
	l.state.statusMu.RLock()
	defer l.state.statusMu.RUnlock()
	return l.state.status
}

var ErrInvalidStatus = errors.New("invalid status")

func (l *looper) SetStatus(ctx context.Context, status models.LoopStatus) (
	outcome string, err error) {
	l.state.statusMu.Lock()
	defer l.state.statusMu.Unlock()
	existingStatus := l.state.status

	switch status {
	case constants.Running:
		switch existingStatus {
		case constants.Starting, constants.Running, constants.Stopping, constants.Crashed:
			return fmt.Sprintf("already %s", existingStatus), nil
		}
		l.loopLock.Lock()
		defer l.loopLock.Unlock()
		l.state.status = constants.Starting
		l.state.statusMu.Unlock()
		l.start <- struct{}{}

		newStatus := constants.Starting // for canceled context
		select {
		case <-ctx.Done():
		case newStatus = <-l.running:
		}
		l.state.statusMu.Lock()
		l.state.status = newStatus
		return newStatus.String(), nil
	case constants.Stopped:
		switch existingStatus {
		case constants.Stopped, constants.Stopping, constants.Starting, constants.Crashed:
			return fmt.Sprintf("already %s", existingStatus), nil
		}
		l.loopLock.Lock()
		defer l.loopLock.Unlock()
		l.state.status = constants.Stopping
		l.state.statusMu.Unlock()
		l.stop <- struct{}{}

		newStatus := constants.Stopping // for canceled context
		select {
		case <-ctx.Done():
		case <-l.stopped:
			newStatus = constants.Stopped
		}
		l.state.statusMu.Lock()
		l.state.status = newStatus
		return status.String(), nil
	default:
		return "", fmt.Errorf("%w: %s: it can only be one of: %s, %s",
			ErrInvalidStatus, status, constants.Running, constants.Stopped)
	}
}
