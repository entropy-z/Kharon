all:
	@ echo "    * Building agent_kharon plugin"
	@ mkdir -p dist
	@ GOEXPERIMENT=jsonv2,greenteagc go build -buildmode=plugin -ldflags="-s -w" -o ./dist/agent_kharon.so pl_lokycrypt.go pl_main.go pl_agent.go pl_packer.go pl_utils.go
	@ echo "      done..."

	@ echo "    * Building agent_kharon src code"
	@ (cd src_beacon && $(MAKE) prebuild-x64 --no-print-directory)
	@ echo "      done..."
