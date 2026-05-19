package controller

import (
	"bytes"
	"context"

	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

func captureControllerLogs(run func(context.Context)) string {
	var buf bytes.Buffer

	logger := zap.New(zap.WriteTo(&buf), zap.UseDevMode(true))
	ctx := logf.IntoContext(context.Background(), logger)

	run(ctx)

	return buf.String()
}
