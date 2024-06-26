module github.com/slashtechno/api-failover

go 1.19

replace github.com/cloverstd/tcping/ping => ./ping

require (
	github.com/alexflint/go-arg v1.4.3
	github.com/cloudflare/cloudflare-go v0.57.1
	github.com/cloverstd/tcping/ping v0.0.0-00010101000000-000000000000
	github.com/prometheus-community/pro-bing v0.3.0
	github.com/sirupsen/logrus v1.9.2
)

require (
	github.com/alexflint/go-scalar v1.1.0 // indirect
	github.com/google/go-querystring v1.1.0 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/go-retryablehttp v0.7.1 // indirect
	golang.org/x/net v0.11.0 // indirect
	golang.org/x/sync v0.3.0 // indirect
	golang.org/x/sys v0.9.0 // indirect
	golang.org/x/text v0.10.0 // indirect
	golang.org/x/time v0.0.0-20220224211638-0e9765cccd65 // indirect
)
