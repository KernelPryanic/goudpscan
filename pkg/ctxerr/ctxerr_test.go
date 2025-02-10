package ctxerr

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

var ErrCause = errors.New("original error")

func TestWith(t *testing.T) {
	tests := []struct {
		name        string
		err         error
		ctx         map[string]any
		expected    error
		shouldMatch CtxErr
	}{
		{
			name: "basic error wrapping",
			err:  ErrCause,
			ctx: map[string]any{
				"string":       "bar",
				"int":          42,
				"slice_string": []string{"one", "two", "three"},
			},
			expected: ErrCause,
			shouldMatch: CtxErr{
				Err: ErrCause,
				Ctx: map[string]any{
					"string":       "bar",
					"int":          42,
					"slice_string": []string{"one", "two", "three"},
				},
			},
		},
		{
			name: "nil error",
			err:  nil,
			ctx: map[string]any{
				"string":       "bar",
				"int":          42,
				"slice_string": []string{"one", "two", "three"},
			},
			expected: nil,
		},
		{
			name: "override existing context",
			err: With(ErrCause, map[string]any{
				"string":       "bar",
				"int":          42,
				"slice_string": []string{"one", "two", "three"},
			}),
			ctx: map[string]any{
				"newfield":     true,
				"string":       "new value",
				"slice_string": []string{"one"},
			},
			expected: ErrCause,
			shouldMatch: CtxErr{
				Err: ErrCause,
				Ctx: map[string]any{
					"int":          42,              // Original
					"string":       "new value",     // Overridden
					"slice_string": []string{"one"}, // Overridden
					"newfield":     true,            // New
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := With(tt.err, tt.ctx)
			if tt.expected == nil {
				require.Nil(t, result)
				return
			}

			require.ErrorIs(t, result, tt.expected)
			actual, ok := result.(CtxErr)
			require.True(t, ok)
			require.Equal(t, tt.shouldMatch, actual)
		})
	}
}

func TestCtx(t *testing.T) {
	tests := []struct {
		name     string
		ctx      context.Context
		err      error
		expected CtxErr
	}{
		{
			name: "context without error",
			ctx:  context.Background(),
			err:  nil,
			expected: CtxErr{
				Err: nil,
				Ctx: nil,
			},
		},
		{
			name: "basic error in context",
			ctx:  context.Background(),
			err: With(ErrCause, map[string]any{
				"string":       "bar",
				"int":          42,
				"slice_string": []string{"one", "two", "three"},
			}),
			expected: CtxErr{
				Err: ErrCause,
				Ctx: map[string]any{
					"string":       "bar",
					"int":          42,
					"slice_string": []string{"one", "two", "three"},
				},
			},
		},
		{
			name: "override existing context error",
			ctx: Ctx(context.Background(), With(ErrCause, map[string]any{
				"string":       "bar",
				"int":          42,
				"slice_string": []string{"one", "two", "three"},
			})),
			err: With(ErrCause, map[string]any{
				"new": true,
				"int": 404,
			}),
			expected: CtxErr{
				Err: ErrCause,
				Ctx: map[string]any{
					"string":       "bar",
					"slice_string": []string{"one", "two", "three"},
					"int":          404,  // Overridden
					"new":          true, // New
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resultCtx := Ctx(tt.ctx, tt.err)
			actual := From(resultCtx)
			require.Equal(t, tt.expected, actual)
		})
	}
}
