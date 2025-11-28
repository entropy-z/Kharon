all:
	@ echo "    * Building listener_kharon_http plugin"
	@ mkdir -p dist
	@ GOEXPERIMENT=jsonv2,greenteagc go build -buildmode=plugin -ldflags="-s -w" -o ./dist/listener_kharon_http.so pl_lokycrypt.go pl_main.go pl_http.go pl_listener.go
	@ echo "      done..."
