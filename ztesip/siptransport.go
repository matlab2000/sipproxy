package ztesip

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/satori/go.uuid"
)

type ViaKey string // Proto://SentBy

func (v ViaKey) isUDP() bool {
	return strings.HasPrefix(string(v), "UDP")
}

func (v ViaKey) Host() string {
	idx := strings.Index(string(v), "://")
	return string(v)[idx+3:]
}

type UUID string

type Proxy struct {
	Proto Transport //udp,tcp
	Ip    string
	Port  int
	User  string
	Pwd   string
}

type PacketSendMsg struct {
	ID     UUID
	Proto  Transport
	Remote string //*net.UDPAddr //only for udp
	Msg    *SipMsg
}

type ClientInfo struct {
	ID       UUID
	ConnType Transport //proto should be  UDP/TCP/TLS/WS/WSS
	PeerAddr string    //ip:port

	PacketSendCh chan *PacketSendMsg //接收数据通道
	ExitCh       chan interface{}    //接收退出消息通道
}

var wsupgrader = websocket.Upgrader{
	ReadBufferSize:  1024 * 16,
	WriteBufferSize: 1024 * 16,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

func wshandler(w http.ResponseWriter, r *http.Request, isSSL bool) {
	rsphdr := make(http.Header)
	rsphdr.Add("Sec-Websocket-Protocol", "sip")
	rsphdr.Add("Sec-WebSocket-Version", "13")
	conn, err := wsupgrader.Upgrade(w, r, rsphdr)
	if err != nil {
		log.Println("Failed to set websocket upgrade:", err)
		return
	}
	//addr := conn.RemoteAddr()
	//log.Println("ws PeerAddr:", addr.String())
	StreamClient(conn, nil, true, isSSL)
}

func WSSServer(cfg *SipConfig) {
	router := gin.Default()
	router.GET("/", func(c *gin.Context) {
		wshandler(c.Writer, c.Request, true)
	})

	router.RunTLS(fmt.Sprintf(":%d", cfg.WssPort), cfg.CertFileName, cfg.KeyFileName)
}

func WSServer(cfg *SipConfig) {
	router := gin.Default()
	router.GET("/", func(c *gin.Context) {
		wshandler(c.Writer, c.Request, false)
	})
	router.Run(fmt.Sprintf(":%d", cfg.WsPort))
}

func checkError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal error: %s", err.Error())
		os.Exit(1)
	}
}

// client and mgr

type MgrConfig struct {
	CreateCh     chan *CreateMsg     //主控接收创建
	DestroyCh    chan *DestroyMsg    //主控接收销毁
	PacketRecvCh chan *PacketRecvMsg //主控接收数据通道
	StatusCh     chan *StatusMsg     //主控接收状态数据
}

func NewMgrConfig() *MgrConfig {
	createCh := make(chan *CreateMsg, 100)
	destroyCh := make(chan *DestroyMsg, 100)
	pktRecvCh := make(chan *PacketRecvMsg, 1000)
	statusCh := make(chan *StatusMsg, 100)
	return &MgrConfig{createCh, destroyCh, pktRecvCh, statusCh}
}

type CreateMsg struct {
	ID           UUID
	ConnType     Transport
	PeerAddr     string              //*net.TCPAddr
	PacketSendCh chan *PacketSendMsg //客户端构建，主控可以向该通道发送数据
	ExitCh       chan interface{}    //主控发送退出消息到客户端
}

type DestroyMsg struct {
	ID UUID
}

type StatusMsg struct {
	ID   UUID
	Code int
	Desc string
}

type PacketRecvMsg struct {
	ID  UUID
	Msg *SipMsg
}

type ClientMgr struct {
	LocalIP   string //local ip
	UdpPort   int
	Clients   map[UUID]*ClientInfo //ID
	ViaTable  map[ViaKey]UUID
	NameTable map[string]UUID //when called,we can use user name to uuid[callee]
	Route     map[*regexp.Regexp]*Proxy
	UdpID     UUID
	Cfg       *MgrConfig //config
	SipCfg    *SipConfig
}

var Config *MgrConfig

func NewClientMgr(cfg *SipConfig) *ClientMgr {
	Config = NewMgrConfig()

	m := make(map[UUID]*ClientInfo)
	vt := make(map[ViaKey]UUID)
	nt := make(map[string]UUID)
	r := make(map[*regexp.Regexp]*Proxy)

	ips := LocalIps()
	ip := ips[0].String()
	UdpListeningPort := cfg.UdpPort

	go UdpMain(ip, UdpListeningPort) //

	var pat *regexp.Regexp
	for _, route := range cfg.Route {

		if route.IsPrefix {
			pat = regexp.MustCompile("^" + route.Rule)
		} else {
			pat = regexp.MustCompile(route.Rule + "$")
		}
		proxy := &Proxy{route.Proto, route.Ip, route.Port, route.Username, route.Password}
		r[pat] = proxy
	}

	return &ClientMgr{LocalIP: ip, UdpPort: UdpListeningPort, Clients: m, ViaTable: vt,
		NameTable: nt, Route: r, UdpID: UUID(""), Cfg: Config, SipCfg: cfg}
}

func (mgr *ClientMgr) Add(msg *CreateMsg) error {
	id := msg.ID

	if _, ok := mgr.Clients[id]; !ok {
		c := &ClientInfo{id, msg.ConnType, msg.PeerAddr, msg.PacketSendCh, msg.ExitCh}
		mgr.Clients[id] = c
	} else {
		log.Printf("Client Mgr Add,but has got ID %s\n", id)
	}

	if msg.ConnType == UDP {
		mgr.UdpID = id
	}
	return nil
}

func (mgr *ClientMgr) Remove(id UUID) error {
	if mgr.UdpID == id {
		mgr.UdpID = ""
	}
	if _, ok := mgr.Clients[id]; ok {
		delete(mgr.Clients, id)
	} else {
		log.Printf("Client Mgr Remove,but has no ID %s\n", id)
	}

	//delete ViaTable's value is UUID's item
	keys := []ViaKey{}
	for k, v := range mgr.ViaTable {
		if v == id {
			keys = append(keys, k)
		}
	}

	for _, key := range keys {
		delete(mgr.ViaTable, key)
	}

	return nil
}

func (mgr *ClientMgr) Send(id UUID, proto Transport, remote string, msg *SipMsg) error {
	if c, ok := mgr.Clients[id]; ok {
		if proto == UDP {
			m := &PacketSendMsg{id, proto, remote, msg}
			c.PacketSendCh <- m
		} else {
			//log.Println("proto:", string(proto), " remote:", remote, " c.PeerAddr:", c.PeerAddr)
			if strings.HasSuffix(remote, ".invalid") || remote == c.PeerAddr {
				m := &PacketSendMsg{id, proto, remote, msg}
				c.PacketSendCh <- m

			} else {
				if proto == TLS || proto == TCP {
					//create new transport
					CreateTcpTls(remote, msg, proto == TLS)
				} else if proto == WS || proto == WSS {
					CreateWsWss(remote, msg, proto == WSS)
				}
			}
		}

	} else {
		log.Printf("send,but has no ID %s\n", id)
	}

	return nil
}

var uri_pat = regexp.MustCompile(`^sips?\s*:\s*([^:@]+)?@?([^:$]+)?:?(\d+)?.*$`)

//if user   [1]user [2]domain [3]port
//if no user  [1]domain [2]  [3]port

//首先检查，如果top via就是以前记录链接上的的，那么查找route表
//如果来源不是

func (mgr *ClientMgr) ReceiveRequest(id UUID, msg *SipMsg) error {
	//record
	via, _ := msg.TopVia()
	k := via.Key()
	if _, ok := mgr.ViaTable[ViaKey(k)]; ok {
		//log.Println("via table has key", k)
	} else {
		//log.Println("via add id ", id, " to via ", k)
	}
	mgr.ViaTable[ViaKey(k)] = id
	//route
	uri := msg.SipUri()
	s := uri_pat.FindStringSubmatch(uri)
	user := s[1]
	domain := s[2]
	if len(s[2]) == 0 {
		domain = s[1]
		user = ""
	}

	var destProxy *Proxy = nil

	for pat, proxy := range mgr.Route {
		if pat.MatchString(domain) || (len(user) != 0 && pat.MatchString(user)) {
			destProxy = proxy
		}
	}

	if destProxy != nil {
		//fmt.Printf("destProxy ok %+v\n", destProxy)
		if destProxy.Proto == UDP {
			//send to udp
			if mgr.UdpID != "" {
				if _, ok := mgr.Clients[mgr.UdpID]; ok {
					addr := fmt.Sprintf("%s:%d", destProxy.Ip, destProxy.Port)
					mgr.Send(mgr.UdpID, UDP, addr, msg)
				}
			}
		} else {
			//send to tcp
			if destProxy.Proto == TLS || destProxy.Proto == TCP {
				addr := fmt.Sprintf("%s:%d", destProxy.Ip, destProxy.Port)
				CreateTcpTls(addr, msg, destProxy.Proto == TLS)
			} else {
				fmt.Printf("ReceiveRequest send to %s by ws/wss not implement\n", destProxy.Ip)
			}
		}

	} else {
		//response with 404?
		log.Println("no dest proxy for uri:", uri)
	}
	return nil
}

func (mgr *ClientMgr) ReceiveResponse(id UUID, msg *SipMsg) error {
	msg.RemoveTopVia()

	via, _ := msg.TopVia()
	k := via.Key()
	if uid, ok := mgr.ViaTable[ViaKey(k)]; ok {
		if _, ok := mgr.Clients[uid]; ok {
			if via.Transport == UDP {
				//log.Println("Resonse but via is UDP ", via.String())
				mgr.Send(mgr.UdpID, UDP, via.SentBy, msg)
			} else {
				//log.Println("Resonse via is ", via.String())
				mgr.Send(uid, via.Transport, via.SentBy, msg)
			}

		} else {
			log.Println("can't find client by uid ", uid)
		}
	} else {
		log.Println("can't find uid by via key ", k)
	}
	return nil
}

func (mgr *ClientMgr) Receive(id UUID, msg *SipMsg) error {

	//fmt.Printf("receive msg %v\n", msg.OrigMsg())

	route, err := msg.TopRoute()
	if err == nil {
		s := route.ToSipUri()
		fl := msg.FirstLine()
		fla := strings.Split(fl, " ")
		fla[1] = s
		msg.SetFirstLine(strings.Join(fla, " "))
		msg.RemoveTopRoute()
	}

	//处理register消息
	if msg.Method() == REGISTER {
		if msg.IsRequest() == true {
			//modify contact
			c := msg.Contact()
			if c.Transport == WS || c.Transport == WSS {
				c.Username = msg.ToUserName()
				c.Domain = fmt.Sprintf("%s:%d", mgr.LocalIP, mgr.UdpPort)
				c.Transport = UDP
			}
		} else {
			//fmt.Println("register response")
		}
	}

	ourvia, _ := msg.TopVia()
	st := strings.Split(ourvia.SentBy, ":")
	if st[0] != mgr.LocalIP {
		if msg.IsRequest() {
			//fmt.Printf("not local ip recv Request %v\n", msg)
			return mgr.ReceiveRequest(id, msg)
		} else {
			//TODO: should be request, send back error
			//fmt.Printf("not local ip recv Response %v\n", msg)
			return mgr.ReceiveResponse(id, msg)
		}
	} else {
		if !msg.IsRequest() {
			//fmt.Printf("recv Response %v\n", msg)
			return mgr.ReceiveResponse(id, msg)
		} else {
			//fmt.Printf("recv Request %v\n", msg)
			return mgr.ReceiveRequest(id, msg)
			//TODO: should be response,  send back error
		}

	}
	return nil
}

func (mgr *ClientMgr) Run() error {

	for {
		select {
		case cm := <-mgr.Cfg.CreateCh:
			fmt.Println("CreateCh")
			mgr.Add(cm)
		case dm := <-mgr.Cfg.DestroyCh:
			mgr.Remove(dm.ID)
			fmt.Println("DestroyCh")
		case rm := <-mgr.Cfg.PacketRecvCh:
			mgr.Receive(rm.ID, rm.Msg)
			fmt.Println("PacketRecvCh")
		case <-mgr.Cfg.StatusCh:
			fmt.Println("StatusCh")

		}
	}
	return nil
}

func CreateTcpTls(host string, msg *SipMsg, isSSL bool) {
	//log.Printf("create tcp tls %s isSSL %b\n", host, isSSL)
	conn, err := net.Dial("tcp", host)
	if err != nil {
		log.Println("CreateTcpTls error:", err)
		return
	}
	if isSSL {
		conf := &tls.Config{
			InsecureSkipVerify: true,
		}
		tls.Client(conn, conf)
	}
	go StreamClient(conn, msg, false, isSSL)
}

func CreateWsWss(host string, msg *SipMsg, isSSL bool) {
	//log.Printf("create ws wss %s isSSL %b\n", host, isSSL)
	var u *url.URL
	if isSSL {
		u = &url.URL{Scheme: "wss", Host: host, Path: ""}
	} else {
		u = &url.URL{Scheme: "ws", Host: host, Path: ""}
	}
	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	d := &websocket.Dialer{Subprotocols: []string{"sip"},
		TLSClientConfig: tlsConfig}

	conn, _, err := d.Dial(u.String(), nil)
	if err != nil {
		log.Println("dial ws wss error:", err)
		return
	}

	go StreamClient(conn, msg, true, isSSL)
}

const sock_msg_len = 16 * 1024

var ctxlen_pat = regexp.MustCompile(`(?m)(?:Content-Length|l):\s*(\d+)`)

func extractSip(s *string) int {
	vs := *s
	idx := strings.Index(vs, "\r\n\r\n")
	if idx == -1 {
		return -1
	}
	value := ctxlen_pat.FindStringSubmatch(vs[:idx])
	v, _ := strconv.ParseInt(value[1], 10, 32)
	total := idx + 4 + int(v)
	if len(vs) >= total {
		return total
	} else {
		return -1
	}

}

func GetRemote(ctype Transport, conn interface{}) net.Addr {
	var ra net.Addr
	if ctype == WS || ctype == WSS {
		ra = conn.(*websocket.Conn).RemoteAddr()
	} else if ctype == TLS || ctype == TCP {
		ra = conn.(*net.TCPConn).RemoteAddr()
	} else {
		log.Printf("GetRemote but ctype %s not ok\n", string(ctype))
	}
	addr, _ := net.ResolveTCPAddr(ra.Network(), ra.String())
	return addr
}

func StreamClient(conn interface{}, firstmsg *SipMsg, isws bool, isSSL bool) error {

	var wg sync.WaitGroup
	var cType Transport

	u := UUID(uuid.NewV4().String())
	log.Println("ws client uid ", u)
	exitCh := make(chan interface{})
	pktSendCh := make(chan *PacketSendMsg, 10)

	//for write gorouting
	writeExitCh := make(chan interface{})

	if isSSL {
		if isws {
			cType = WSS
		} else {
			cType = TLS
		}
	} else {
		if isws {
			cType = WS
		} else {
			cType = TCP
		}
	}

	if firstmsg != nil {
		sendmsg := &PacketSendMsg{u, UNKNOWN, "", firstmsg}
		pktSendCh <- sendmsg
	}

	addr := GetRemote(cType, conn)
	createMsg := &CreateMsg{u, cType, addr.String(), pktSendCh, exitCh}
	Config.CreateCh <- createMsg

	wg.Add(2)
	//read
	go func() {
		recvbuf := make([]byte, sock_msg_len)
		recvstr := "" //
		defer wg.Done()
		var sipmsg *SipMsg

		for {
			if isws {
				_, msg, err := conn.(*websocket.Conn).ReadMessage() //t
				if err != nil {
					log.Printf("websocket read error %v\n", err)
					break
				}
				sipmsg = NewSipMsg(msg)
			} else {
				n, err := conn.(*net.TCPConn).Read(recvbuf)
				if err != nil {
					log.Printf("tcp socket read error %v\n", err)
					break
				}
				recvstr += string(recvbuf[:n])
				msglen := extractSip(&recvstr)
				if msglen == -1 {
					//log.Println("extractSip but msglen is -1 recvstr len:", len(recvstr))
					continue
				} else {
					msg := recvstr[:msglen]
					sipmsg = NewSipMsg([]byte(msg))
					recvstr = recvstr[msglen:]
				}

			}

			Config.PacketRecvCh <- &PacketRecvMsg{u, sipmsg}
		}

		writeExitCh <- struct{}{}
	}()

	//write
	go func() {
		writeRunning := true
		defer wg.Done()
	WRITE_START:
		for writeRunning == true {
			select {
			case pktsend := <-pktSendCh:
				msg := pktsend.Msg
				if isws == false && msg.IsRequest() == true {
					//Add Via
					local := conn.(*net.TCPConn).LocalAddr().String()
					v := NewVia(cType, local, "z9hG4bK"+msg.FromTag())
					msg.AddTopVia(v)
				}
				data, err := msg.Encode()
				if err == nil {
					if isws == true {
						err = conn.(*websocket.Conn).WriteMessage(websocket.TextMessage, data)
						if err != nil {
							log.Println("websocket write message error:", err)
							writeRunning = false
							break WRITE_START
						} else {
							//addr := conn.(*websocket.Conn).RemoteAddr()
							//log.Println("write message [", string(data), "] ok remote:", addr.String())
						}
					} else {
						//log.Printf("tcp write data [%s]\n", string(data))
						total := len(data)
						hassent := 0
						for hassent < total {
							n, err := conn.(*net.TCPConn).Write(data[hassent:])
							if n <= 0 || err != nil {
								log.Println("write  error:", err)
								writeRunning = false
								break WRITE_START
							}
							hassent += n
						}
					}

				} else {
					log.Println("encode error:", err)
					writeRunning = false
					break WRITE_START
				}
			case <-writeExitCh:
				//log.Println("write Exit ch!!!")
				writeRunning = false
				break WRITE_START
			}
		}
		exitCh <- struct{}{}
	}()

	select {
	case <-exitCh:
		if cType == WS || cType == WSS {
			conn.(*websocket.Conn).Close()
		} else if cType == TLS || cType == TCP {
			conn.(*net.TCPConn).Close()
		} else {
			log.Printf("Close Conn but ctype %s not ok\n", string(cType))
		}
	}

	wg.Wait()

	//destroy message
	destroyMsg := &DestroyMsg{u}
	Config.DestroyCh <- destroyMsg
	log.Println("client uid exit", u)
	return nil
}

func UdpMain(ip string, port int) {
	var wg sync.WaitGroup
	var host = ip + ":" + strconv.Itoa(port)
	u := UUID(uuid.NewV4().String())
	exitCh := make(chan interface{})
	pktSendCh := make(chan *PacketSendMsg, 10)
	//for write gorouting
	writeExitCh := make(chan interface{})
	//start tcp server
	addr, err := net.ResolveUDPAddr("udp", host)
	if err != nil {
		log.Fatalln("net.ResolveUDPAddr fail.", err)
		return
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalln("net.ListenUDP fail.", err)
		return
	}
	log.Println("start udp server " + ip + " " + strconv.Itoa(port))
	//defer conn.Close()

	//create message
	//laddr := conn.LocalAddr()
	createMsg := &CreateMsg{u, UDP, "", pktSendCh, exitCh}
	Config.CreateCh <- createMsg

	wg.Add(2)
	//read
	go func() {
		defer wg.Done()
		recvbuf := make([]byte, sock_msg_len)

		for {
			rlen /*remote*/, _, err := conn.ReadFromUDP(recvbuf) //t
			if err != nil {
				log.Printf("read udp error %v\n", err)
				break
			}
			if rlen <= 0 {
				log.Printf("read udp error readlen %d\n", rlen)
				break
			}
			sipmsg := NewSipMsg(recvbuf[:rlen])
			fmt.Printf("udp read ok\n")
			Config.PacketRecvCh <- &PacketRecvMsg{UUID(u), sipmsg}
		}

	}()

	//write
	go func() {
		defer wg.Done()
		for {
			select {
			case pktsend := <-pktSendCh:
				log.Println("udp recv pkt to write")
				msg := pktsend.Msg
				if msg.IsRequest() {
					//Add Via
					v := NewVia(UDP, host, "z9hG4bK"+msg.FromTag())
					msg.AddTopVia(v)
				}
				data, err := msg.Encode()
				if err == nil {
					addr, err := net.ResolveUDPAddr("udp", pktsend.Remote)
					if err != nil {
						log.Printf("ResolveUDPAddr %s error %v\n", pktsend.Remote, err)
						continue
					}
					_, err = conn.WriteToUDP(data, addr)
					if err != nil {
						log.Printf("write to udp %s error %v\n", pktsend.Remote, err)
					}
					fmt.Printf("udp write\n")
				} else {
					log.Printf("msg encode error %v\n", err)
				}
			case <-writeExitCh:
				log.Println("udp write recv exit")
				break
			}
		}

	}()

	for {
		select {
		case <-exitCh:
			conn.Close()
			break
		}
	}

	wg.Wait()
	//destroy message
	destroyMsg := &DestroyMsg{u}
	Config.DestroyCh <- destroyMsg

}
