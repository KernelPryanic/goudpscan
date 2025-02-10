// Package ctxerr provides functions to extract context information from errors.
package ctxerr

import "context"

// CtxErr is an error type that contains contextual information fields
// related to the error. It's used to propagate fields up the call stack.
type CtxErr struct {
	// Err is the original wrapped error.
	Err error

	// Ctx holds contextual information associated with Err.
	Ctx map[string]any
}

func (e CtxErr) Error() string { return e.Err.Error() }
func (e CtxErr) Unwrap() error { return e.Err }

// With adds the error context values by wrapping err into ctxerr.Error.
// Use this to propagate contextual information up the call stack.
//
// Example:
//
//	return ctxerr.With(err, map[string]any{"user_id": 1})
func With(err error, errCtx map[string]any) error {
	if err == nil {
		return nil
	}
	if ctxErr, ok := err.(CtxErr); ok {
		for key, value := range errCtx {
			ctxErr.Ctx[key] = value
		}
		return ctxErr
	}
	return CtxErr{Err: err, Ctx: errCtx}
}

// ctxKey is a context key for storing CtxErr objects.
type ctxKey struct{}

// From reads the error from ctx, if any.
func From(ctx context.Context) CtxErr {
	if v, ok := ctx.Value(ctxKey{}).(CtxErr); ok {
		return v
	}
	return CtxErr{}
}

// Ctx adds the context error to ctx.
// Use this to pass the context error to the logger.
// Logger will automatically extract the error with its context values and log them.
// Example:
//
//	logger.Error().Ctx(ctxerr.Ctx(context.Background(), err)).Msg("an error occurred")
func Ctx(ctx context.Context, ctxErr error) context.Context {
	if ctxErr == nil {
		return ctx
	}
	err := ctxErr
	var ctxMapNew map[string]any
	if ctxErrExisting, ok := ctx.Value(ctxKey{}).(CtxErr); ok {
		// There's already an error with context in ctx,
		// Use its context values as a basis.
		ctxMapNew = make(map[string]any, len(ctxErrExisting.Ctx))
		for key, value := range ctxErrExisting.Ctx {
			ctxMapNew[key] = value
		}
	}
	if ctxErrNew, ok := ctxErr.(CtxErr); ok {
		err = ctxErrNew.Err
		if ctxMapNew == nil {
			// There was no existing error with context in ctx.
			// Initialize context values map.
			ctxMapNew = make(map[string]any, len(ctxErrNew.Ctx))
		}
		// Override existing values.
		for key, value := range ctxErrNew.Ctx {
			ctxMapNew[key] = value
		}
	}
	return context.WithValue(ctx, ctxKey{}, CtxErr{Err: err, Ctx: ctxMapNew})
}
