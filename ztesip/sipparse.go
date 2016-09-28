package ztesip

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

//*Regexp
var (
	via_re     = regexp.MustCompile(`^SIP/2.0/([^ \t]+)\s+([^;]+);(?:.*;)?branch=(\w+).*$`)
	from_re    = regexp.MustCompile(`^([^ <]+)?\s*<(?:sips?:([^@]+)@([^>;]+);?(?:transport=(\w+).*)?)>\s*(?:;tag=([.\d\w]+))?.*$`)
	contact_re = regexp.MustCompile(`^([^ <]+)?\s*<(?:sips?:([^@]+)@([^>;]+);?(?:transport=(\w+).*?)?)>\s*;?.*?(?:expires=(\d+))?.*$`)
	route_re   = regexp.MustCompile(`^\s*<sips?:(?:([^@]+)@)?([^>;:]+)(?::(\d+))?;?(lr)?>$`)
)

type Method string

const (
	INVITE    Method = "INVITE"
	ACK       Method = "ACK"
	CANCEL    Method = "CANCEL"
	BYE       Method = "BYE"
	REGISTER  Method = "REGISTER"
	OPTIONS   Method = "OPTIONS"
	SUBSCRIBE Method = "SUBSCRIBE"
	NOTIFY    Method = "NOTIFY"
	REFER     Method = "REFER"
)

type SipMsgCodec interface {
	Encode() ([]byte, error)
	Decode(data []byte) error
}

type SipMsgCollecter struct {
	data   []byte
	msgPtr []int
}

func (c *SipMsgCollecter) Add(data []byte) error {
	return nil
}

func (c *SipMsgCollecter) Remove() (*SipMsg, error) {
	return nil, nil
}

func (c *SipMsgCollecter) Count() int {
	return 0
}

type Transport string

const (
	UNKNOWN Transport = "UNKNOWN"
	UDP     Transport = "UDP"
	TCP     Transport = "TCP"
	TLS     Transport = "TLS"
	WS      Transport = "WS"
	WSS     Transport = "WSS"
	SCTP    Transport = "SCTP"
)

type ConnectionType int

const (
	Udp ConnectionType = 1 << iota
	Tcp
	Tls
	Ws
	Wss
	Sctp
)

//Via: SIP/2.0/WSS ha0af4gnfvl8.invalid;branch=z9hG4bK1497770
type Via struct {
	Transport Transport
	SentBy    string
	Branch    string
}

func NewVia(trans Transport, host string, branch string) *Via {
	return &Via{trans, host, branch}
}

func ParseVia(s string) *Via {

	r := &Via{}
	ms := via_re.FindStringSubmatch(s)
	r.Transport = Transport(ms[1])
	r.SentBy = ms[2]
	r.Branch = ms[3]

	return r
}

func (v *Via) String() string {
	s := fmt.Sprintf("Via: SIP/2.0/%s %s", v.Transport, v.SentBy)
	if len(v.Branch) > 0 {
		s += ";branch=" + v.Branch
	}
	return s
}

func (v *Via) Key() string {
	return fmt.Sprintf("%s://%s", v.Transport, v.SentBy)
}

func (v *Via) IsDataGram() bool {
	return v.Transport == UDP
}

func (v *Via) Host() string {
	return v.SentBy
}

type Route struct {
	Username string
	Domain   string
	Port     int
	IsStrict bool
}

func NewRoute(Username, Domain string, Port int, IsStrict bool) *Route {
	return &Route{Username, Domain, Port, IsStrict}
}

func ParseRoute(s string) *Route {

	r := &Route{}
	ms := route_re.FindStringSubmatch(s)
	r.Username = ms[1]
	r.Domain = ms[2]
	v, _ := strconv.ParseInt(ms[3], 10, 32)
	r.Port = int(v)
	r.IsStrict = (ms[4] != "lr")

	return r
}

//func (r *Route) Username() string {
//	return r.Username
//}

//func (r *Route) Domain() string {
//	return r.Domain
//}

//func (r *Route) IsStrict() bool {
//	return r.IsStrict
//}

func (r *Route) String() string {
	s := "Route: <sip:"
	if len(r.Username) > 0 {
		s += r.Username + "@"
	}
	s += r.Domain
	if r.Port != 0 {
		s += fmt.Sprintf(":%d", r.Port)
	}
	if r.IsStrict == false {
		s += ";lr"
	}
	s += ">"

	return s
}

func (r *Route) ValString() string {
	s := "<sip:"
	if len(r.Username) > 0 {
		s += r.Username + "@"
	}
	s += r.Domain
	if r.Port != 0 {
		s += fmt.Sprintf(":%d", r.Port)
	}
	if r.IsStrict == false {
		s += ";lr"
	}
	s += ">"
	return s
}

func (r *Route) ToSipUri() string {
	s := "sip:"
	if len(r.Username) > 0 {
		s += r.Username + "@"
	}
	s += r.Domain
	if r.Port != 0 {
		s += fmt.Sprintf(":%d", r.Port)
	}

	return s
}

//From: <sip:alice@kf.zte.com.cn>;tag=bmsu89m4gi
type FromTo struct {
	IsFrom      bool
	Displayname string
	Username    string
	Domain      string
	Tag         string
}

func NewFromTo(isfrom bool, display, user, domain, tag string) *FromTo {
	return &FromTo{isfrom, display, user, domain, tag}
}

func ParseFromTo(isfrom bool, s string) *FromTo {
	r := &FromTo{}
	ms := from_re.FindStringSubmatch(s)
	//fmt.Printf("FromTo: s:[%s] ms:%t\n", s, ms)
	r.Displayname = ms[1]
	r.Username = ms[2]
	r.Domain = ms[3]
	r.Tag = ms[5]
	return r
}

func (f *FromTo) String() string {
	r := ""
	if f.IsFrom == true {
		r += "From: "
	} else {
		r += "To: "
	}

	if len(f.Displayname) > 0 {
		r += f.Displayname + " "
	}
	r += fmt.Sprintf("<sip:%s@%s>", f.Username, f.Domain)
	if len(f.Tag) > 0 {
		r += ";tag=" + f.Tag
	}
	return r
}

//Contact: <sip:bpe4fc20@ha0af4gnfvl8.invalid;transport=ws>;
//expires=300;+sip.ice;reg-id=1;+sip.instance="<urn:uuid:93d317d6-3e58-42d1-a456-b56e1b30e33f>"
type Contact struct {
	Displayname string
	Username    string
	Domain      string
	Transport   Transport
	Expires     int
}

func NewContact(display, user, domain string, trans Transport, expires int) *Contact {
	return &Contact{display, user, domain, trans, expires}
}

func (c *Contact) String() string {
	r := "Contact: "
	if len(c.Displayname) > 0 {
		r += c.Displayname
	}
	r += fmt.Sprintf(" <%s@%s", c.Username, c.Domain)
	if len(c.Transport) > 0 {
		r += ";transport=" + strings.ToLower(string(c.Transport))
	}
	r += ">"
	if c.Expires != -1 {
		r += fmt.Sprintf(";expires=%d", c.Expires)
	}
	return r
}

func ParseContact(s string) *Contact {
	r := &Contact{}
	ms := contact_re.FindStringSubmatch(s)
	r.Displayname = ms[1]
	r.Username = ms[2]
	r.Domain = ms[3]
	if len(ms[4]) > 0 {
		r.Transport = Transport(ms[4])
	} else {
		r.Transport = UDP
	}
	if len(ms[5]) > 0 {
		v, _ := strconv.ParseInt(ms[5], 10, 32)
		r.Expires = int(v)
	} else {
		r.Expires = -1
	}

	return r
}

type SipMsg struct {
	rawdata []byte
	data    []byte
	//-----------------
	isRequest   bool
	firstline   string
	sipuri      string
	method      Method
	vias        []*Via
	routes      []*Route
	from        *FromTo
	to          *FromTo
	contact     *Contact
	callid      string
	seq         int
	expires     int
	maxforwards int

	//hasSep  bool //是否遇到\r\n\r\n
	body    []byte
	bodyLen int
	//-----------------
	headers map[string]string
	orders  []string
	//-----------------
	recvAddr string // proto://ip:port
}

func NewSipMsg(data []byte) *SipMsg {
	m := &SipMsg{rawdata: data,
		vias:    []*Via{},
		headers: make(map[string]string),
		//orders:  []string{},
	}
	m.Decode()
	return m
}

func (msg *SipMsg) FirstLine() string {
	return msg.firstline
}

func (msg *SipMsg) SetFirstLine(s string) {
	msg.firstline = s
	sa := strings.Fields(s)
	msg.sipuri = sa[1]
}

func (msg *SipMsg) RecvAddr() string {
	return msg.recvAddr
}

func (msg *SipMsg) SetRecvAddr(addr string) error {
	msg.recvAddr = addr
	return nil
}

func (msg *SipMsg) FromTag() string {
	return msg.from.Tag
}

func (msg *SipMsg) ToUserName() string {
	return msg.to.Username
}

func (msg *SipMsg) IsRequest() bool {
	return msg.isRequest
}

func (msg *SipMsg) SipUri() string {
	return msg.sipuri
}

func (msg *SipMsg) Method() Method {
	return msg.method
}

func (msg *SipMsg) Contact() *Contact {
	return msg.contact
}

func (msg *SipMsg) SetContact(c *Contact) error {
	msg.contact = c
	return nil
}

func (msg *SipMsg) Encode() ([]byte, error) {
	var b bytes.Buffer
	b.WriteString(msg.firstline + "\r\n")
	for _, name := range msg.orders {
		switch name {
		case "Via":
			for _, via := range msg.vias {
				b.WriteString(via.String() + "\r\n")
			}
		case "Route":
			if len(msg.routes) > 0 {
				b.WriteString("Route: ")
				ba := []string{}
				for _, route := range msg.routes {
					ba = append(ba, route.ValString())
				}
				bs := strings.Join(ba, ",")
				b.WriteString(bs + "\r\n")
			}
		case "Max-Forwards":
			b.WriteString(fmt.Sprintf("Max-Forwards: %d\r\n", msg.maxforwards-1))
		default:
			b.WriteString(name + ": " + msg.headers[name] + "\r\n")
		}
	}

	b.WriteString("\r\n")

	if msg.bodyLen > 0 {
		b.Write(msg.body)
	}

	msg.data = b.Bytes()
	return msg.data, nil
}

func (msg *SipMsg) OrigMsg() string {
	return string(msg.rawdata)
}

func (msg *SipMsg) String() string {

	return string(msg.data)
}

func (msg *SipMsg) AddTopVia(v *Via) error {
	msg.vias = append([]*Via{v}, msg.vias...)
	return nil
}

func (msg *SipMsg) TopVia() (*Via, error) {
	if len(msg.vias) > 0 {
		return msg.vias[0], nil
	} else {
		return nil, errors.New("no top via")
	}

}

func (msg *SipMsg) RemoveTopVia() error {
	if len(msg.vias) > 1 {
		msg.vias = msg.vias[1:]
	} else {
		msg.vias = []*Via{}
	}
	return nil
}

func (msg *SipMsg) TopRoute() (*Route, error) {
	if len(msg.routes) > 0 {
		return msg.routes[0], nil
	} else {
		return nil, errors.New("no top route")
	}
}

func (msg *SipMsg) RemoveTopRoute() error {
	if len(msg.routes) > 1 {
		msg.routes = msg.routes[1:]
	} else {
		msg.routes = []*Route{}
	}
	return nil
}

func (msg *SipMsg) Decode() error {
	m := string(msg.rawdata)
	idx := strings.Index(m, "\r\n\r\n")
	if idx == -1 {
		return errors.New("sip msg not complete")
	}
	hdrs := m[:idx]
	lines := strings.Split(hdrs, "\n")
	msg.firstline = strings.TrimSpace(lines[0])
	fields := strings.Split(msg.firstline, " ")
	if fields[0] == "SIP/2.0" {
		//response
		msg.isRequest = false
	} else {
		//request
		msg.method = Method(fields[0])
		msg.sipuri = fields[1]
		msg.isRequest = true
	}
	headers := lines[1:]
	for _, line := range headers {
		fields = strings.SplitN(line, ":", 2)
		name := strings.TrimSpace(fields[0])
		value := strings.TrimSpace(fields[1])
		if len(msg.orders) == 0 {
			msg.orders = []string{name}
		} else {
			if msg.orders[len(msg.orders)-1] != name {
				msg.orders = append(msg.orders, name)
			}
		}
		switch name {
		case "Via":
			v := ParseVia(value)
			if v != nil {
				msg.vias = append(msg.vias, v)
			} else {
				fmt.Printf("can't parse %s to Via\n", value)
			}
		case "Route":
			ra := strings.Split(value, ",")
			for _, r := range ra {
				r := ParseRoute(r)
				if r != nil {
					msg.routes = append(msg.routes, r)
				} else {
					fmt.Printf("can't parse %s to Route\n", value)
				}
			}
		case "From":
			msg.from = ParseFromTo(true, value)
			msg.headers[name] = value
		case "To":
			msg.to = ParseFromTo(false, value)
			msg.headers[name] = value
		case "Contact":
			msg.contact = ParseContact(value)
			msg.headers[name] = value
		case "Call-ID":
			msg.callid = value
			msg.headers[name] = value
		case "Content-Length":
			v, _ := strconv.ParseInt(value, 10, 32)
			msg.bodyLen = int(v)
			if msg.bodyLen > 0 {
				msg.body = msg.rawdata[idx+4:]
			} else {
				msg.body = nil
			}
			msg.headers[name] = value
		case "CSeq":
			fs := strings.Split(value, " ")
			v, _ := strconv.ParseInt(fs[0], 10, 32)
			msg.seq = int(v)
			if msg.isRequest == false {
				msg.method = Method(fs[1])
			}
			msg.headers[name] = value
		case "Max-Forwards":
			v, _ := strconv.ParseInt(value, 10, 32)
			msg.maxforwards = int(v)
		default:
			msg.headers[name] = value
		}

	}
	return nil
}
