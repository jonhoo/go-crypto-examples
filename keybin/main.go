package main

import (
	"bytes"
	"fmt"
	"keys"
	"net/http"
	"os"
	"runtime"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("%s: <server|client>\n", os.Args[0])
		os.Exit(1)
	}
	if os.Args[1] == "server" {
		err := keys.Server("localhost", authenticate, handler)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}

	if os.Args[1] == "client" {
		err := keys.Client("alice", "localhost", func(c *http.Client) {
			// TODO: use c to contact /secure on server
			r, err := c.Get("https://localhost:8443/secure")
			if err != nil {
				fmt.Println("connection to /secure failed:", err)
				os.Exit(3)
				return
			}

			var buf bytes.Buffer
			buf.ReadFrom(r.Body)
			fmt.Println("got", buf.String(), "from /secure")
			os.Exit(0)
		})
		if err != nil {
			fmt.Println(err)
			os.Exit(2)
		}

		fmt.Println("client - server handshake completed")
		for {
			runtime.Gosched()
		}
	}
}

func authenticate(username string, password string) error {
	// TODO: verify the client's credentials
	return nil
}

func handler(w http.ResponseWriter, rq *http.Request) {
	// TODO: Handle request to /secure from securely authorized user
	w.Write([]byte("hello"))
}
