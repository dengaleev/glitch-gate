package shorten

import "context"

type URLStorage interface {
	InsertURL(ctx context.Context, short, long string) error
}

type Shortener struct{}

func New() *Shortener {
	return &Shortener{}
}

func (svc *Shortener) ShortenURL(ctx context.Context, longURL string) (string, error) {
	const op = "shorten.Service.ShortenURL"

	return "", nil
}
