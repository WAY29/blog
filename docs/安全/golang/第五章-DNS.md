---
created: '21/06/06 08:55'
title: 第五章-DNS
tags:
  - golang
---

# 第五章-DNS

主要学习[dns](https://github.com/miekg/dns)这个第三包的使用

### FQDN

一个简单的dns的*fully qualified domain name* (fqdn)请求,使用A记录,并输出结果

 ```Go
 package main
 
 import (
   "fmt"
 
   "github.com/miekg/dns"
 )
 
 func main() {
   var msg dns.Msg
   fqdn := dns.Fqdn("stacktitan.com")
   msg.SetQuestion(fqdn, dns.TypeA)
   in, err := dns.Exchange(&msg, "8.8.8.8:53")
   if err != nil {
     panic(err)
   }
   if len(in.Answer) < 1 {
     fmt.Println("No records")
     return
   }
 
   for _, answer := range in.Answer {
     if a, ok := answer.(*dns.A); ok {
       fmt.Println(a.A)
     }
   }
 
 }
 ```


简单地分析一下,`in`这个变量类型是dns.Msg,而Msg的结构如下

 ```Go
 type Msg struct {
  MsgHdr
  Compress bool `json:"-"` // If true, the message will be compressed...
  u Question []Question // Holds the RR(s) of the question section.
  v Answer []RR // Holds the RR(s) of the answer section.
  Ns []RR // Holds the RR(s) of the authority section.
  Extra []RR // Holds the RR(s) of the additional section.
 }
 ```


而RR则是一个接口,需要实现以下几个方法

 ```Go
 type RR interface {
   // Header returns the header of an resource record. The header contains
   // everything up to the rdata.
   Header() *RR_Header
   // String returns the text representation of the resource record.
   String() string
 
   // copy returns a copy of the RR
   copy() RR
 
   // len returns the length (in octets) of the compressed or uncompressed RR in wire format.
   //
   // If compression is nil, the uncompressed size will be returned, otherwise the compressed
   // size will be returned and domain names will be added to the map for future compression.
   len(off int, compression map[string]struct{}) int
 
   // pack packs the records RDATA into wire format. The header will
   // already have been packed into msg.
   pack(msg []byte, off int, compression compressionMap, compress bool) (off1 int, err error)
 
   // unpack unpacks an RR from wire format.
   //
   // This will only be called on a new and empty RR type with only the header populated. It
   // will only be called if the record's RDATA is non-empty.
   unpack(msg []byte, off int) (off1 int, err error)
 
   // parse parses an RR from zone file format.
   //
   // This will only be called on a new and empty RR type with only the header populated.
   parse(c *zlexer, origin string) *ParseError
 
   // isDuplicate returns whether the two RRs are duplicates.
   isDuplicate(r2 RR) bool
 }
 ```


最后遍历answer(变量类型是RR),这里有一个强制转换`a, ok := answer.(*dns.A); ok`,将RR类型强制转换为*dns.A,而dns.A的相关结构又如下,可以看到dns.A组合了RR_Header这个类型,而RR_Header实现了RR的方法,因此dns.A可以是RR类型

 ```Go
 // A RR. See RFC 1035.
 type A struct {
   Hdr RR_Header
   A   net.IP `dns:"a"`
 }
 
 // RR_Header is the header all DNS resource records share.
 type RR_Header struct {
   Name     string `dns:"cdomain-name"`
   Rrtype   uint16
   Class    uint16
   Ttl      uint32
   Rdlength uint16 // Length of data after header.
 }
 
 // Header returns itself. This is here to make RR_Header implements the RR interface.
 func (h *RR_Header) Header() *RR_Header { return h }
 
 // Just to implement the RR interface.
 func (h *RR_Header) copy() RR { return nil }
 // ...
 ```


### subdomain_fuzzer

参考blackhat-go里subdomain_guesser写的,一个简单的根据字典通过dns查询爆破子域名的工具,核心基本一样,但是由于原作者写的协程并发代码有点难以理解,所以稍微修改了一下,使用了[sizedwaitgroup](https://github.com/remeh/sizedwaitgroup)这个包

 ```Go
 package main
 
 import (
   "bufio"
   "errors"
   "flag"
   "fmt"
   "os"
 
   "github.com/miekg/dns"
   "github.com/remeh/sizedwaitgroup"
 )
 
 //
 type Result struct {
   IpAddress string
   Hostname  string
 }
 
 //
 func LookupA(fqdn, serverAddr string) ([]string, error) {
   var m dns.Msg
   var ips []string
   m.SetQuestion(dns.Fqdn(fqdn), dns.TypeA)
   in, err := dns.Exchange(&m, serverAddr)
 
   if err != nil {
     return ips, err
   }
   if len(in.Answer) < 1 {
     return ips, errors.New("No answer")
   }
   for _, answer := range in.Answer {
     if a, ok := answer.(*dns.A); ok {
       ips = append(ips, a.A.String())
     }
   }
   return ips, nil
 }
 
 func LookupCNAME(fqdn, serverAddr string) ([]string, error) {
   var m dns.Msg
   var fqdns []string
   m.SetQuestion(dns.Fqdn(fqdn), dns.TypeCNAME)
   in, err := dns.Exchange(&m, serverAddr)
   if err != nil {
     return fqdns, err
   }
   if len(in.Answer) < 1 {
     return fqdns, errors.New("No answer")
   }
   for _, answer := range in.Answer {
     if c, ok := answer.(*dns.CNAME); ok {
       fqdns = append(fqdns, c.Target)
     }
   }
   return fqdns, nil
 }
 
 //
 func Lookup(fqdn, serverAddr string) []Result {
   var results []Result
   var cfqdn = fqdn
   for {
     cnames, err := LookupCNAME(cfqdn, serverAddr)
     if err == nil && len(cnames) > 0 {
       cfqdn = cnames[0]
       continue
     }
     ips, err := LookupA(cfqdn, serverAddr)
     if err != nil {
       break
     }
     for _, ip := range ips {
       results = append(results, Result{
         IpAddress: ip,
         Hostname:  fqdn,
       })
     }
     break
   }
   return results
 }
 
 func worker(fqdn string, serverAddr string, resultChannel chan []Result, swg *sizedwaitgroup.SizedWaitGroup) {
   results := Lookup(fqdn, serverAddr)
   if len(results) > 0 {
     resultChannel <- results
   }
   return
 }
 
 func main() {
   var (
     flDomain      = flag.String("domain", "", "The domain to perform fuzzing against.")
     flWordlist    = flag.String("wordlist", "", "The wordlist to use for fuzzing")
     flWorkerCount = flag.Int("c", 100, "The amount of worker to use")
     flServerAddr  = flag.String("server", "8.8.8.8:53", "The DNS server to use")
   )
   flag.Parse()
   if *flDomain == "" || *flWordlist == "" {
     fmt.Println("domain and wordlist are rquired")
     os.Exit(1)
   }
 
   swg := sizedwaitgroup.New(*flWorkerCount)
   resultsChannel := make(chan []Result)
   var results []Result
 
   go func() { // ? read from channel immediately
     for r := range resultsChannel {
       for _, result := range r {
         fmt.Printf("%s\t%s\n", result.Hostname, result.IpAddress)
       }
       results = append(results, r...)
       swg.Done()
     }
   }()
 
   fh, err := os.Open(*flWordlist)
   if err != nil {
     fmt.Println("Cannot read " + *flWordlist)
     os.Exit(2)
   }
   defer fh.Close()
   reader := bufio.NewReader(fh)
 
   for {
     bytes, _, err := reader.ReadLine()
     line := string(bytes[:])
     if err != nil {
       break
     }
     swg.Add()
     go worker(fmt.Sprintf("%s.%s", line, *flDomain), *flServerAddr, resultsChannel, &swg)
   }
   swg.Wait()
   close(resultsChannel)
   fmt.Println("\nResult:\n-----------------------------------------------")
   for _, r := range results {
     fmt.Printf("%s\t%s\n", r.Hostname, r.IpAddress)
   }
 }
 
 ```
