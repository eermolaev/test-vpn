// Command vlessdiag runs the stage-by-stage VLESS check against the profile
// in a JSON file (profile.VLESSConfig), optionally overriding the SNI.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/eermolaev/test-vpn/core/engine/xray"
	"github.com/eermolaev/test-vpn/core/profile"
)

func main() {
	sni := flag.String("sni", "", "override the server name")
	port := flag.Int("port", 0, "override the port")
	n := flag.Int("n", 1, "attempts")
	flag.Parse()
	b, err := os.ReadFile(flag.Arg(0))
	if err != nil {
		panic(err)
	}
	var c profile.VLESSConfig
	if err := json.Unmarshal(b, &c); err != nil {
		panic(err)
	}
	if *sni != "" {
		c.SNI = *sni
	}
	if *port != 0 {
		c.Port = *port
	}
	for i := 0; i < *n; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		start := time.Now()
		err := xray.Diagnose(ctx, &c, netip.MustParseAddrPort("8.8.8.8:53"))
		cancel()
		fmt.Printf("%s sni=%s port=%d: %v (%s)\n", time.Now().Format("15:04:05"), c.SNI, c.Port, err, time.Since(start).Round(time.Millisecond))
	}
}
