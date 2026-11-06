module github.com/singleaxis/singleaxis-fabric/components/host-emitter

go 1.26.0

require (
	github.com/cilium/ebpf v0.22.0
	github.com/singleaxis/singleaxis-fabric/components/otel-collector-fabric/hostrecords v0.0.0-00010101000000-000000000000
	go.opentelemetry.io/collector/pdata v1.56.0
	golang.org/x/sys v0.49.0
	google.golang.org/grpc v1.85.0
)

require (
	github.com/hashicorp/go-version v1.9.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.3-0.20250322232337-35a7c28c31ee // indirect
	go.opentelemetry.io/collector/featuregate v1.56.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/net v0.62.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260817212433-ac3dfec99bb1 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)

// The host-records library (spec 056 §7.3.3 (b)) is built from this
// repository; the Docker build context is components/ for that reason.
replace github.com/singleaxis/singleaxis-fabric/components/otel-collector-fabric/hostrecords => ../otel-collector-fabric/hostrecords
