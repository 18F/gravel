package dns

type DnsProvider struct {
	RecordHandler chan DnsMessage
}

func NewDnsProvider(recordHandler chan DnsMessage) *DnsProvider {
	return &DnsProvider{RecordHandler: recordHandler}
}

// Message used to ferry the provider challenges to the DNS server.
type DnsMessage struct {
	Domain, Token, KeyAuth string
}

func (d *DnsProvider) Present(domain, token, keyAuth string) error {
	d.RecordHandler <- DnsMessage{Domain: domain, Token: token, KeyAuth: keyAuth}
	return nil
}

func (d *DnsProvider) CleanUp(domain, token, keyAuth string) error {
	return nil
}
