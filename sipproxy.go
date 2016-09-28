package main

import (
	"bufio"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"

	"github.com/gin-gonic/gin"

	"./ztesip"
)

func proxyGet(c *gin.Context) {
	c.JSON(200, gin.H{
		"status":  "posted",
		"message": "msg",
		"nick":    "nick",
	})
}

func callGet(c *gin.Context) {
	c.JSON(200, gin.H{
		"status":  "posted",
		"message": "msg",
		"nick":    "nick",
	})
}

//<?xml version="1.0" encoding="utf-8"?>

type Id struct {
	Id int `xml:"id"`
}

type User struct {
	//XMLName xml.Name `xml:"author"`
	Id   int    `xml:"id"`
	Name string `xml:"name"`
	Age  int    `xml:"age"`
}

//
func userGet(c *gin.Context) {
	body := c.Request.Body
	x, _ := ioutil.ReadAll(body)

	defer body.Close()

	//fmt.Printf("%v %s \n", x, string(x))

	id := Id{}
	v := "<body>" + string(x) + "</body>"
	xml.Unmarshal([]byte(v), &id)
	//c.BindWith(id, binding.XML)
	fmt.Printf("bind %+v\n", id)
	u := &User{Id: id.Id, Name: "xueys", Age: 37}
	b, _ := xml.Marshal(u)
	c.Data(http.StatusOK, "application/xml", []byte(xml.Header+string(b)))

}

func web(cfg *ztesip.SipConfig) {

	//ztesip.ParseSip()

	router := gin.Default()
	// Simple group: v1
	v1 := router.Group("/api/v1")
	{
		v1.GET("/proxy", proxyGet)
		v1.GET("/call", callGet)
		v1.GET("/user", userGet)
		v1.POST("/user", userGet)
	}

	// vd := router.Group("/api/v1/debug")
	// {
	//  vd.GET("/certfile",certfileGet)
	//  vd.GET("/inifile",inifileGet)
	//  vd.GET("/transaction",transactionGet)
	//  vd.GET("/transuser",transuserGet)
	//  vd.GET("/register",registerGet)
	//  vd.GET("/network",networkGet)
	//  vd.GET("/config",configGet)
	//  vd.GET("/log",logGet)
	//  vd.POST("/thread",threadPost)
	// }

	router.Run(fmt.Sprintf(":%d", cfg.HttpPort))
}

func testSipMsg() {
	bytes, err := ioutil.ReadFile("pkt/wsreg.txt")
	if err != nil {
		return
	}
	msg := ztesip.NewSipMsg(bytes)

	ips := ztesip.LocalIps()
	host := ips[0].String() + ":5060"

	v := ztesip.NewVia(ztesip.UDP, host, "z9hG4bK"+msg.FromTag())
	msg.AddTopVia(v)

	data, _ := msg.Encode()

	fmt.Printf("%s\n", data)
}

func testSipConfig() {
	cfg := ztesip.NewSipConfig(ztesip.SipConfigName)
	fmt.Printf(cfg.String())
}

//var cpuprofile = flag.String("cpuprofile", "", "write cpu profile to file")

func tcpServer(cfg *ztesip.SipConfig) {
	fmt.Println("Launching server...")

	// listen on all interfaces
	ln, _ := net.Listen("tcp", fmt.Sprintf(":%d", cfg.XmlPort))

	// accept connection on port
	conn, _ := ln.Accept()

	// run loop forever (or until ctrl-c)
	for {
		// will listen for message to process ending in newline (\n)
		message, _ := bufio.NewReader(conn).ReadString('\n')
		// output message received
		if len(message) > 0 {
			fmt.Print("Message Received:", string(message))
		}
		// sample process for string received
		newmessage := "<User><name>xue</name><age>37</age></User>"
		// send new string back to client
		conn.Write([]byte(newmessage + "\x00"))
	}

}

func main() {
	//	fmt.Printf("cpu %d\n", runtime.NumCPU())
	//	if *cpuprofile != "" {
	//		f, err := os.Create(*cpuprofile)
	//		if err != nil {
	//			log.Fatal(err)
	//		}
	//		pprof.StartCPUProfile(f)
	//		defer pprof.StopCPUProfile()
	//	}

	// gin.SetMode(gin.ReleaseMode)
	cfg := ztesip.NewSipConfig(ztesip.SipConfigName)

	go tcpServer(cfg)
	go web(cfg)
	go ztesip.WSServer(cfg)
	go ztesip.WSSServer(cfg)

	mgr := ztesip.NewClientMgr(cfg)
	mgr.Run()
}
