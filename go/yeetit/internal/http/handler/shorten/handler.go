package shorten

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
)

type request struct {
	LongURL string `json:"long_url"`
}

type errorResponse struct {
	Message string `json:"message"`
}

type response struct {
	ShortURL string `json:"short_url"`
}

type LinkShortener interface {
	ShortenURL(ctx context.Context, longURL string) (string, error)
}

func slErr(err error) slog.Attr { return slog.String("error", err.Error()) }

func New(logger *slog.Logger, shortener LinkShortener) http.Handler {
	logger = logger.With("component", "http.handler.shorten")

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			logger.WarnContext(r.Context(), "failed to decode request body", slErr(err))
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(errorResponse{Message: "Invalid request body"})
			return
		}

		if req.LongURL == "" {
			logger.WarnContext(r.Context(), "long URL is required")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(errorResponse{Message: "Long URL is required"})
			return
		}

		shortURL, err := shortener.ShortenURL(r.Context(), req.LongURL)
		if err != nil {
			logger.WarnContext(r.Context(), "failed to shorten URL", slErr(err))
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(errorResponse{Message: "Failed to shorten URL"})
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response{ShortURL: shortURL})
	})
}
