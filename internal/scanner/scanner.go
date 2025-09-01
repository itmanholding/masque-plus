package scanner

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"time"

	"masque-plus/internal/logutil"

	"github.com/quic-go/quic-go"
)

var defaultScanPerIPTimeout = 3 * time.Second

type Result struct {
	Endpoint  string
	OK        bool
	Err       string
	Elapsed   time.Duration
	Transport string // "quic" or "tcp-tls"
}

type Options struct {
	PerIPTimeout time.Duration
	UseQUIC      bool
	TLSConfig    *tls.Config
	QUICConfig   *quic.Config
}

type Option func(*Options)

func WithPerIPTimeout(d time.Duration) Option { return func(o *Options) { o.PerIPTimeout = d } }
func WithQUIC(enabled bool) Option            { return func(o *Options) { o.UseQUIC = enabled } }
func WithTLSConfig(c *tls.Config) Option      { return func(o *Options) { o.TLSConfig = c } }
func WithQUICConfig(c *quic.Config) Option    { return func(o *Options) { o.QUICConfig = c } }

func isHandshakeErr(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "handshake") ||
		strings.Contains(s, "crypto_error") ||
		strings.Contains(s, "tls: handshake") ||
		strings.Contains(s, "remote error") ||
		strings.Contains(s, "quic:") ||
		strings.Contains(s, "alert") ||
		strings.Contains(s, "bad certificate")
}

func ScanEndpoints(endpoints []string, opts ...Option) []Result {
	o := Options{
		PerIPTimeout: defaultScanPerIPTimeout,
		UseQUIC:      true,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true, // for scanning only
			NextProtos:         []string{"h3", "h3-29", "h3-32", "h3-34"},
		},
		QUICConfig: &quic.Config{
			HandshakeIdleTimeout: defaultScanPerIPTimeout,
			MaxIdleTimeout:       defaultScanPerIPTimeout,
			KeepAlivePeriod:      0,
		},
	}
	for _, f := range opts {
		f(&o)
	}
	if o.PerIPTimeout <= 0 {
		o.PerIPTimeout = defaultScanPerIPTimeout
	}
	if o.QUICConfig != nil {
		o.QUICConfig.HandshakeIdleTimeout = o.PerIPTimeout
		o.QUICConfig.MaxIdleTimeout = o.PerIPTimeout
	}

	results := make([]Result, 0, len(endpoints))

	for _, ep := range endpoints {
		start := time.Now()
		success, err := tryEndpointScan(ep, o)
		elapsed := time.Since(start)

		if err != nil {
			switch {
			case isHandshakeErr(err):
				logutil.Info("handshake failed; skipping endpoint", map[string]string{
					"endpoint": ep,
					"elapsed":  elapsed.String(),
					"err":      err.Error(),
				})
			case errors.Is(err, context.DeadlineExceeded):
				logutil.Info("scan timeout; skipping endpoint", map[string]string{
					"endpoint": ep,
					"timeout":  o.PerIPTimeout.String(),
				})
			default:
				logutil.Info("connection failed; skipping endpoint", map[string]string{
					"endpoint": ep,
					"err":      err.Error(),
				})
			}
			results = append(results, Result{
				Endpoint:  ep,
				OK:        false,
				Err:       err.Error(),
				Elapsed:   elapsed,
				Transport: transportName(o),
			})
			continue
		}

		logutil.Info("endpoint ok", map[string]string{
			"endpoint": ep,
			"elapsed":  elapsed.String(),
			"mode":     transportName(o),
		})
		results = append(results, Result{
			Endpoint:  ep,
			OK:        success,
			Err:       "",
			Elapsed:   elapsed,
			Transport: transportName(o),
		})
	}

	return results
}

func transportName(o Options) string {
	if o.UseQUIC {
		return "quic"
	}
	return "tcp-tls"
}

func tryEndpointScan(ep string, o Options) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), o.PerIPTimeout)
	defer cancel()

	if o.UseQUIC {
		tconf := cloneTLS(o.TLSConfig)

		// Set SNI only if host is a hostname (not an IP).
		if isHostPort(ep) {
			host, _ := splitHostPort(ep)
			if net.ParseIP(host) == nil && tconf.ServerName == "" {
				tconf.ServerName = host
			}
		}

		sess, err := quic.DialAddr(ctx, ep, tconf, o.QUICConfig)
		if err != nil {
			return false, err
		}
		_ = sess.CloseWithError(0, "")
		return true, nil
	}

	d := &net.Dialer{Timeout: o.PerIPTimeout}
	conn, err := tls.DialWithDialer(d, "tcp", ep, o.TLSConfig)
	if err != nil {
		return false, err
	}
	_ = conn.Close()
	return true, nil
}

func isHostPort(s string) bool {
	_, _, err := net.SplitHostPort(s)
	return err == nil
}

func splitHostPort(s string) (string, string) {
	h, p, _ := net.SplitHostPort(s)
	return h, p
}

func cloneTLS(c *tls.Config) *tls.Config {
	if c == nil {
		return &tls.Config{}
	}
	cp := *c
	return &cp
}
