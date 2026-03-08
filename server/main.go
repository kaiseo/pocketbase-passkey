package main

import (
	"log"
	"os"

	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
)

func main() {
	app := pocketbase.New()

	setupPasskey(app)

	// Explicitly serve static files from pb_public
	app.OnServe().BindFunc(func(e *core.ServeEvent) error {
		e.Router.GET("/{path...}", apis.Static(os.DirFS("./pb_public"), true))
		return e.Next()
	})

	if err := app.Start(); err != nil {
		log.Fatal(err)
	}
}
