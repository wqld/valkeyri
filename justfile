build:
    cargo xtask build-ebpf
    cargo build --target $(uname -m)-unknown-linux-musl
    docker build --build-arg ARCH=$(uname -m) -t valkeyri:test .

build-and-load-image:
    cargo xtask build-ebpf
    cargo build --target $(uname -m)-unknown-linux-musl
    docker build --build-arg ARCH=$(uname -m) -t valkeyri:test .
    kind load docker-image valkeyri:test

run-debug-container:
    kubectl debug redis-master-0 --image=valkeyri:test --profile='sysadmin' -it
