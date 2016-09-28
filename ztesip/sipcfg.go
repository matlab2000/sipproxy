package ztesip

import (
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/ini.v1"
)

const SipConfigName string = "ztesip.ini"

//10.114.70.166 = *;ccm1000.zte.com.cn[;udp:5060[;user;pwd]]
type SipRoute struct {
	IsPrefix bool
	Ip       string
	Port     int
	Proto    Transport
	Rule     string //userno@domain   ^userno or domain$
	Username string
	Password string
}

func NewSipRoute() *SipRoute {
	return &SipRoute{}
}

func (r *SipRoute) Parse(name, val string) error {
	r.Ip = name
	arr := strings.Split(val, ",") // maybe ;
	if arr[0] == "*" {
		r.IsPrefix = false
		r.Rule = arr[1]
	} else {
		r.IsPrefix = true
		r.Rule = arr[0]
	}
	r.Proto = UDP
	r.Port = 5060
	if len(arr) >= 3 {
		arr1 := strings.Split(arr[2], ":")
		r.Proto = Transport(strings.ToUpper(arr1[0]))
		if len(arr1) > 1 {
			p, _ := strconv.ParseInt(arr1[1], 10, 32)
			r.Port = int(p)
		}
	}
	r.Username = ""
	r.Password = ""
	if len(arr) >= 4 {
		r.Username = arr[3]
	}
	if len(arr) >= 5 {
		r.Password = arr[4]
	}
	return nil
}

func (r *SipRoute) String() string {
	name, val := r.NameVal()
	return fmt.Sprintf("%s=%s", name, val)
}

func (r *SipRoute) NameVal() (string, string) {

	val := ""
	if r.IsPrefix == true {
		val += fmt.Sprintf("%s,*", r.Rule)
	} else {
		val += fmt.Sprintf("*,%s", r.Rule)
	}

	if r.Proto != UDP || r.Port != 5060 {
		val += fmt.Sprintf(",%s:%d", r.Proto, r.Port)
	}

	if len(r.Username) > 0 && len(r.Password) > 0 {
		val += fmt.Sprintf(",%s;%s", r.Username, r.Password)
	}

	return r.Ip, val
}

type SipConfig struct {
	Home         string
	MaxLinkNum   int
	HttpPort     int
	HttpsPort    int
	UdpPort      int
	TcpPort      int
	TlsPort      int
	WsPort       int
	WssPort      int
	XmlPort      int
	CertFileName string
	KeyFileName  string
	LogLevel     int
	LogPath      string

	Route      map[string]*SipRoute
	RouteOrder []string

	//
	cfg   *ini.File
	fname string
}

func NewSipConfig(fname string) *SipConfig {

	sipcfg := &SipConfig{}
	sipcfg.Route = make(map[string]*SipRoute)
	sipcfg.RouteOrder = []string{}

	cfg, err := ini.Load([]byte{}, fname)
	if err == nil {
		sipcfg.cfg = cfg
		sipcfg.fname = fname
		sipcfg.ReadIni()
	}

	return sipcfg
}

func (sipcfg *SipConfig) AddRoute(r *SipRoute) error {

	if _, ok := sipcfg.Route[r.Ip]; !ok {
		//not duplicate
		sipcfg.RouteOrder = append(sipcfg.RouteOrder, r.Ip)
	}
	routeSec := sipcfg.cfg.Section("Route")
	name, val := r.NameVal()
	routeSec.Key(name).SetValue(val)
	sipcfg.Route[r.Ip] = r
	return nil
}

func (sipcfg *SipConfig) RemoveRoute(ip string) error {

	if _, ok := sipcfg.Route[ip]; ok {
		delete(sipcfg.Route, ip)
		routeSec := sipcfg.cfg.Section("Route")
		routeSec.DeleteKey(ip)

		//remove ip from RouteOrder
		order := []string{}
		for _, name := range sipcfg.RouteOrder {
			if name != ip {
				order = append(order, name)
			}
		}
		sipcfg.RouteOrder = order
	}

	return nil
}

func (sipcfg *SipConfig) ReadIni() error {

	cfg := sipcfg.cfg
	proxySec := cfg.Section("ProxyServer")
	sipcfg.Home = proxySec.Key("Home").Value()
	sipcfg.MaxLinkNum, _ = proxySec.Key("MaxLinkNum").Int()
	sipcfg.HttpPort, _ = proxySec.Key("HttpPort").Int()
	sipcfg.HttpsPort, _ = proxySec.Key("HttpsPort").Int()
	sipcfg.UdpPort, _ = proxySec.Key("UdpPort").Int()
	sipcfg.TcpPort, _ = proxySec.Key("TcpPort").Int()
	sipcfg.TlsPort, _ = proxySec.Key("TlsPort").Int()
	sipcfg.WsPort, _ = proxySec.Key("WsPort").Int()
	sipcfg.WssPort, _ = proxySec.Key("WssPort").Int()
	sipcfg.XmlPort, _ = proxySec.Key("XmlPort").Int()
	routeSec := cfg.Section("Route")
	names := routeSec.KeyStrings()

	for _, name := range names {
		v := routeSec.Key(name).Value()

		r := NewSipRoute()
		result := r.Parse(name, v)
		if result == nil {
			sipcfg.RouteOrder = append(sipcfg.RouteOrder, name)
			sipcfg.Route[name] = r
		}
	}

	securitySec := cfg.Section("Security")
	sipcfg.CertFileName = securitySec.Key("CertFile").Value()
	sipcfg.KeyFileName = securitySec.Key("KeyFile").Value()

	logSec := cfg.Section("Log")
	sipcfg.LogLevel, _ = logSec.Key("LogLevel").Int()
	sipcfg.LogPath = logSec.Key("LogPath").Value()

	return nil
}

func (sipcfg *SipConfig) String() string {
	s := []string{}
	s = append(s, "Home="+sipcfg.Home)
	s = append(s, "MaxLinkNum="+strconv.FormatInt(int64(sipcfg.MaxLinkNum), 10))
	s = append(s, "HttpPort="+strconv.FormatInt(int64(sipcfg.HttpPort), 10))
	s = append(s, "HttpsPort="+strconv.FormatInt(int64(sipcfg.HttpsPort), 10))
	s = append(s, "UdpPort="+strconv.FormatInt(int64(sipcfg.UdpPort), 10))
	s = append(s, "TcpPort="+strconv.FormatInt(int64(sipcfg.TcpPort), 10))
	s = append(s, "TlsPort="+strconv.FormatInt(int64(sipcfg.TlsPort), 10))
	s = append(s, "WsPort="+strconv.FormatInt(int64(sipcfg.WsPort), 10))
	s = append(s, "WssPort="+strconv.FormatInt(int64(sipcfg.WssPort), 10))
	s = append(s, "XmlPort="+strconv.FormatInt(int64(sipcfg.XmlPort), 10))
	s = append(s, "CertFileName="+sipcfg.CertFileName)
	s = append(s, "KeyFileName="+sipcfg.KeyFileName)
	s = append(s, "LogLevel="+strconv.FormatInt(int64(sipcfg.LogLevel), 10))
	s = append(s, "LogPath="+sipcfg.LogPath)

	for _, name := range sipcfg.RouteOrder {
		sr := sipcfg.Route[name]
		s = append(s, sr.String())
	}

	return strings.Join(s, "\n")
}

func (sipcfg *SipConfig) Load(fname string) error {
	if sipcfg.fname != fname {
		cfg, err := ini.Load([]byte{}, fname)
		if err == nil {
			sipcfg.cfg = cfg
			sipcfg.fname = fname

			sipcfg.ReadIni()
		}

	}
	return nil
}

func (sipcfg *SipConfig) Save(fname string) error {
	if sipcfg.cfg != nil {
		sipcfg.cfg.SaveTo(fname)
	}
	return nil
}
